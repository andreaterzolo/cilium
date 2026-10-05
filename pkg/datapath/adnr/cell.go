// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import "github.com/cilium/hive/cell"

const componentName = "auto-direct-node-routes"

var Cell = cell.Module(
	componentName,
	"Maintains routes to node PodCIDRs on the same L2 segment",
	cell.Provide(NewHandler),
)
