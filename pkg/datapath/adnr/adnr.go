// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/cidr"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type Handler struct {
	routeManager     *routeReconciler.DesiredRouteManager
	routeInitializer routeReconciler.Initializer
	db               *statedb.DB
	routes           statedb.Table[*tables.Route]
	desiredRoutes    statedb.Table[*routeReconciler.DesiredRoute]
	logger           *slog.Logger
	cfg              *option.DaemonConfig
}

func NewHandler(
	logger *slog.Logger,
	routeManager *routeReconciler.DesiredRouteManager,
	db *statedb.DB,
	routes statedb.Table[*tables.Route],
	desiredRoutes statedb.Table[*routeReconciler.DesiredRoute],
	cfg *option.DaemonConfig,
) *Handler {
	return &Handler{
		logger:           logger,
		routeManager:     routeManager,
		routeInitializer: routeManager.RegisterInitializer("adnr"),
		db:               db,
		routes:           routes,
		desiredRoutes:    desiredRoutes,
		cfg:              cfg,
	}
}

func getOwnerName(nodeName string) string {
	const adnrOwnerPrefix = "adnr/"
	return adnrOwnerPrefix + nodeName
}

func isDirectRoute(route *tables.Route, ip netip.Addr) bool {
	// `route.Gw == ip` is kept as a defensive check, see:
	// https://github.com/cilium/cilium/pull/8513
	return route.Dst.Contains(ip) &&
		(!route.Gw.IsValid() || route.Gw == ip)
}

func isNodeOnSameL2(
	nodeIP net.IP,
	routes statedb.Table[*tables.Route],
	db *statedb.DB,
) bool {
	ip, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return false
	}
	// Unmap the IP to ensure IPv4-mapped IPv6 addresses are converted to IPv4.
	ip = ip.Unmap()
	for route := range routes.All(db.ReadTxn()) {
		// We iterate all routes until we find a direct route if present.
		if isDirectRoute(route, ip) {
			return true
		}
	}
	return false
}

func (h *Handler) getNodeRoutes(nodeName string, nodeIP net.IP, podCIDRs []netip.Prefix) ([]routeReconciler.DesiredRoute, error) {
	if !isNodeOnSameL2(nodeIP, h.routes, h.db) {
		if h.cfg.DirectRoutingSkipUnreachable {
			h.logger.Debug(
				"route to destination is not reachable, skipping it",
				logfields.NodeName, nodeName,
			)
			return nil, nil
		}
		return nil, fmt.Errorf("route to node %s is not reachable. Add `direct-routing-skip-unreachable` to skip unreachable routes", nodeName)
	}

	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return nil, fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}

	routes := make([]routeReconciler.DesiredRoute, 0, len(podCIDRs))
	ip, ok := netip.AddrFromSlice(nodeIP)
	if !ok {
		return nil, fmt.Errorf("invalid node IP for node %q: %v", nodeName, nodeIP)
	}
	for _, prefix := range podCIDRs {
		routes = append(routes, routeReconciler.DesiredRoute{
			Owner:         owner,
			Table:         routeReconciler.TableMain,
			Prefix:        prefix,
			AdminDistance: routeReconciler.AdminDistanceDefault,
			Nexthop:       ip.Unmap(),
		})
	}
	return routes, nil
}

func (h *Handler) replaceOwnerRoutes(owner *routeReconciler.RouteOwner, newRoutes []routeReconciler.DesiredRoute) error {
	desiredRoutes := make(map[routeReconciler.DesiredRouteKey]routeReconciler.DesiredRoute, len(newRoutes))
	for _, route := range newRoutes {
		desiredRoutes[route.GetFullKey()] = route
	}

	currentRoutes := slices.Collect(statedb.ToSeq(h.desiredRoutes.Prefix(
		h.db.ReadTxn(),
		routeReconciler.DesiredRouteIndex.Query(routeReconciler.DesiredRouteKey{Owner: owner}),
	)))
	for _, current := range currentRoutes {
		desired, exists := desiredRoutes[current.GetFullKey()]
		if !exists {
			if err := h.routeManager.DeleteRoute(*current); err != nil {
				return err
			}
			continue
		}

		delete(desiredRoutes, current.GetFullKey())
		if current.SameSpec(&desired) {
			continue
		}
		if err := h.routeManager.UpsertRoute(desired); err != nil {
			return err
		}
	}

	for _, route := range desiredRoutes {
		if err := h.routeManager.UpsertRoute(route); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) DeleteNodeRoutes(nodeName string) error {
	owner, err := h.routeManager.GetOwner(getOwnerName(nodeName))
	if err != nil {
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}
		return fmt.Errorf("getting route owner for node %s: %w", nodeName, err)
	}
	return h.routeManager.RemoveOwner(owner)
}

func (h *Handler) ReplaceNodeRoutes(n *types.Node) error {
	routes := []routeReconciler.DesiredRoute{}
	nodeName := n.Fullname()
	if h.cfg.EnableIPv4 {
		ipv4Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(false), cidrsToPrefixes(n.GetIPv4AllocCIDRs()))
		if err != nil {
			return err
		}
		routes = append(routes, ipv4Routes...)
	}
	if h.cfg.EnableIPv6 {
		ipv6Routes, err := h.getNodeRoutes(nodeName, n.GetNodeIP(true), cidrsToPrefixes(n.GetIPv6AllocCIDRs()))
		if err != nil {
			return err
		}
		routes = append(routes, ipv6Routes...)
	}
	owner, err := h.routeManager.GetOrRegisterOwner(getOwnerName(nodeName))
	if err != nil {
		return fmt.Errorf("registering route owner for node %s: %w", nodeName, err)
	}
	return h.replaceOwnerRoutes(owner, routes)
}

func (h *Handler) FinalizeInitializer() {
	h.routeManager.FinalizeInitializer(h.routeInitializer)
}

func cidrsToPrefixes(cidrs []*cidr.CIDR) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if c == nil {
			continue
		}
		if prefix, ok := netipx.FromStdIPNet(c.IPNet); ok {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}
