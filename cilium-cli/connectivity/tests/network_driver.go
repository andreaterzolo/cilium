// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	networkDriverName               = "networkdriver.cilium.io"
	networkDriverTestName           = "network-driver-dummy"
	networkDriverDummyDeviceManager = "dummy"
	networkDriverDeviceClassName    = "network-driver-dummy-class"
	networkDriverPoolName           = "network-driver-dummy-pool"
	networkDriverDummyCount         = 8
	networkDriverPollInterval       = 1 * time.Second
	networkDriverTimeout            = 2 * time.Minute
)

type networkDriverScenario struct {
	check.ScenarioBase

	name string
	run  func(context.Context, *check.Test, *networkDriverScenarioEnv)
}

// NetworkDriverScenarios returns the scenarios exercising the network driver.
func NetworkDriverScenarios() []check.Scenario {
	return []check.Scenario{
		newNetworkDriverScenario("multiple-claims", runNetworkDriverMultipleClaims),
	}
}

func newNetworkDriverScenario(name string, run func(context.Context, *check.Test, *networkDriverScenarioEnv)) check.Scenario {
	return &networkDriverScenario{
		ScenarioBase: check.NewScenarioBase(),
		name:         name,
		run:          run,
	}
}

func (s *networkDriverScenario) Name() string { return s.name }

func (s *networkDriverScenario) Run(ctx context.Context, t *check.Test) {
	env := newNetworkDriverScenarioEnv(t)
	defer env.cleanup()
	s.run(ctx, t, env)
}

func runNetworkDriverMultipleClaims(ctx context.Context, _ *check.Test, e *networkDriverScenarioEnv) {
	claimParams, claimParams2 := e.multipleClaimConfigs()
	pod := e.createPod(ctx, claimParams, claimParams2)
	e.waitRunning(ctx, pod)
	e.expectClaimStatus(ctx, pod, "c0", ndDeviceStatus{InterfaceName: "net1", IPs: nonEmpty(claimParams.IPv4Addr, claimParams.IPv6Addr)})
	e.expectClaimStatus(ctx, pod, "c1", ndDeviceStatus{InterfaceName: "net2", IPs: nonEmpty(claimParams2.IPv4Addr, claimParams2.IPv6Addr)})
	e.deletePod(ctx, pod)
}

// Setup configures dummy devices and waits for every node to advertise them.
func SetupNetworkDriverDummy(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
	// Create cluster-wide network driver configuration
	cfg := &ciliumv2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: networkDriverTestName},
		Spec: ciliumv2alpha1.CiliumNetworkDriverClusterConfigSpec{
			Spec: ciliumv2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DeviceManagerConfigs: &ciliumv2alpha1.CiliumNetworkDriverDeviceManagerConfig{
					Dummy: &ciliumv2alpha1.DummyDeviceManagerConfig{Enabled: true, Count: networkDriverDummyCount},
				},
				Pools: []ciliumv2alpha1.CiliumNetworkDriverDevicePoolConfig{{
					PoolName: networkDriverPoolName,
					Filter:   &ciliumv2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{networkDriverDummyDeviceManager}},
				}},
			},
		},
	}
	client := ct.K8sClient()
	createdConfig, err := client.CiliumClientset.CiliumV2alpha1().
		CiliumNetworkDriverClusterConfigs().Create(ctx, cfg, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating ClusterConfig %s: %w", cfg.Name, err)
	}
	t.WithFinalizer(func(ctx context.Context) error {
		err := client.CiliumClientset.CiliumV2alpha1().
			CiliumNetworkDriverClusterConfigs().Delete(ctx, cfg.Name, metav1.DeleteOptions{})
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	})

	// Each node should have its network driver node config ready
	if err := waitForNetworkDriverNodeConfigs(ctx, ct, createdConfig.Spec.Spec); err != nil {
		return err
	}

	// Each node should have its network driver resource slices ready
	if err := waitForNetworkDriverResourceSlices(ctx, ct); err != nil {
		return err
	}

	// Create the DeviceClass for the network driver dummy devices
	dc := &resourceapi.DeviceClass{
		ObjectMeta: metav1.ObjectMeta{Name: networkDriverDeviceClassName},
		Spec: resourceapi.DeviceClassSpec{
			Selectors: []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{
				Expression: fmt.Sprintf(`device.driver == %q && device.attributes[%q].deviceManager == %q`,
					networkDriverName, networkDriverName, networkDriverDummyDeviceManager),
			}}},
		},
	}
	if _, err := client.Clientset.ResourceV1().DeviceClasses().Create(ctx, dc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating DeviceClass %s: %w", networkDriverDeviceClassName, err)
	}
	t.WithFinalizer(func(ctx context.Context) error {
		err := client.Clientset.ResourceV1().DeviceClasses().Delete(ctx, networkDriverDeviceClassName, metav1.DeleteOptions{})
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	})
	return nil
}

func waitForNetworkDriverNodeConfigs(
	ctx context.Context,
	ct *check.ConnectivityTest,
	want ciliumv2alpha1.CiliumNetworkDriverNodeConfigSpec,
) error {
	return wait.PollUntilContextTimeout(
		ctx,
		networkDriverPollInterval,
		networkDriverTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			configs, err := ct.K8sClient().CiliumClientset.CiliumV2alpha1().
				CiliumNetworkDriverNodeConfigs().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, nil
			}
			if len(configs.Items) == 0 ||
				len(configs.Items) != len(ct.CiliumNodes()) {
				return false, nil
			}

			// For each node config, check the specs are ok
			for i := range configs.Items {
				if !configs.Items[i].Spec.DeepEqual(&want) {
					return false, fmt.Errorf("node config spec does not match cluster config spec for node %q",
						configs.Items[i].Name)
				}
			}
			return true, nil
		},
	)
}

func waitForNetworkDriverResourceSlices(
	ctx context.Context,
	ct *check.ConnectivityTest,
) error {
	return wait.PollUntilContextTimeout(
		ctx,
		networkDriverPollInterval,
		networkDriverTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			resourceSlices, err := ct.K8sClient().Clientset.ResourceV1().
				ResourceSlices().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}

			slicePerNode := map[string]resourceapi.ResourceSlice{}
			for _, slice := range resourceSlices.Items {
				spec := slice.Spec
				if spec.Driver != networkDriverName ||
					spec.Pool.Name != networkDriverPoolName ||
					spec.NodeName == nil {
					continue
				}
				nodeName := *spec.NodeName
				if _, ok := slicePerNode[nodeName]; ok {
					return false, fmt.Errorf("multiple resource slices for node %q", nodeName)
				}
				slicePerNode[nodeName] = slice
			}

			for _, node := range ct.CiliumNodes() {
				rs, ok := slicePerNode[node.Name]
				if !ok {
					ct.Logf("no resource slice found for node %q", node.Name)
					return false, nil
				}
				if len(rs.Spec.Devices) != networkDriverDummyCount {
					ct.Logf("expected %d devices in resource slice for node %q, found %d",
						networkDriverDummyCount, node.Name, len(rs.Spec.Devices))
					return false, nil
				}
			}
			return true, nil
		},
	)
}
