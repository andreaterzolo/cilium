// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell provides prefilter, a means of configuring XDP pre-filters for DDoS-mitigation.
var Cell = cell.Module(
	"prefilter",
	"Provides a means of configuring XDP pre-filters for DDoS-mitigation",

	cell.Provide(newPreFilter),
	cell.Provide(newPrefilterApiHandler),
	cell.Invoke(configure),
)

func configure(reg *registry.MapRegistry) error {
	for _, mapCfg := range []struct {
		name       string
		maxEntries uint32
	}{
		{name: datapathmaps.CiliumCIDRV4Fix, maxEntries: maxHKeys},
		{name: datapathmaps.CiliumCIDRV6Fix, maxEntries: maxHKeys},
		{name: datapathmaps.CiliumCIDRV4Dyn, maxEntries: maxLKeys},
		{name: datapathmaps.CiliumCIDRV6Dyn, maxEntries: maxLKeys},
	} {
		if err := reg.Modify(mapCfg.name, func(m *registry.MapSpecPatch) {
			m.MaxEntries = mapCfg.maxEntries
		}); err != nil {
			return fmt.Errorf("failed to update registry for %q: %w",
				mapCfg.name, err)
		}
	}
	return nil
}

type prefilterApiHandlerOut struct {
	cell.Out

	GetPrefilterHandler    prefilter.GetPrefilterHandler
	PatchPrefilterHandler  prefilter.PatchPrefilterHandler
	DeletePrefilterHandler prefilter.DeletePrefilterHandler
}

func newPrefilterApiHandler(prefilter PreFilter) prefilterApiHandlerOut {
	return prefilterApiHandlerOut{
		GetPrefilterHandler:    &getPrefilterHandler{preFilter: prefilter},
		PatchPrefilterHandler:  &patchPrefilterHandler{preFilter: prefilter},
		DeletePrefilterHandler: &deletePrefilterHandler{preFilter: prefilter},
	}
}
