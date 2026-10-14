// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type networkDriver struct{}

func (networkDriver) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("network-driver", ct).
		WithScenarios(tests.NetworkDriver())
}
