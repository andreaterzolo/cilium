// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	iputil "github.com/cilium/cilium/pkg/ip"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ndtypes "github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// nD stands for Network Driver
	// we use a prefix "nD" to avoid clashes with other variables in other tests
	nDName                   = "networkdriver.cilium.io"
	nDClusterConfigName      = "test-cluster-config"
	nDDeviceClassName        = "test-device-class"
	nDStaticIPClaimName      = "test-static-claim"
	nDStaticIPPodName        = "test-static-pod"
	nDIPPoolName             = "test-resource-ip-pool"
	nDIPPoolClaimName        = "test-pool-claim"
	nDIPPoolPodName          = "test-pool-consumer"
	nDPoolName               = "dummy-pool"
	nDDummyDeviceManagerName = "dummy"
	nDClaimRequestName       = "dummy"
	nDNumDevicesPerNode      = 3
)

type networkDriver struct {
	check.ScenarioBase
}

func NetworkDriver() check.Scenario {
	return &networkDriver{ScenarioBase: check.NewScenarioBase()}
}

func (s *networkDriver) Name() string {
	return "network-driver"
}

func (s *networkDriver) Requirements() []features.Requirement {
	// TODO: we probably need ipv4 and ipv6 requirements here as well for the network driver.
	return []features.Requirement{features.RequireEnabled(features.NetworkDriver)}
}

func (s *networkDriver) Run(ctx context.Context, t *check.Test) {
	t.WithFinalizer(func(ctx context.Context) error {
		cleanupNetworkDriverResources(ctx, t)
		return nil
	})

	t.Info("Cleanup Network driver resources if present")
	cleanupNetworkDriverResources(ctx, t)

	t.Info("Creating CiliumNetworkDriverClusterConfig")
	if err := deployClusterConfig(ctx, t); err != nil {
		t.Fatalf("deploying CiliumNetworkDriverClusterConfig: %s", err)
	}

	t.Info("Checking resource slices presence")
	if err := checkResourceSlices(ctx, t); err != nil {
		t.Fatalf("checking resource slices presence: %s", err)
	}

	t.Info("Creating DeviceClass")
	if err := deployDeviceClass(ctx, t); err != nil {
		t.Fatalf("deploying DeviceClass: %s", err)
	}

	t.Info("Creating ResourceClaim with static IPs and Pod")
	if err := deployStaticIPResourceClaimAndPod(ctx, t); err != nil {
		t.Fatalf("deploying static IP ResourceClaim and Pod: %s", err)
	}

	t.Info("Creating CiliumResourceIPPool")
	if err := deployResourceIPPool(ctx, t); err != nil {
		t.Fatalf("deploying CiliumResourceIPPool: %s", err)
	}

	// this should be scheduled on the other node. pay attention to the tolerations...
	t.Info("Creating ResourceClaim with IP pool and Pod")
	if err := deployIPPoolResourceClaimAndPod(ctx, t); err != nil {
		t.Fatalf("deploying IP pool ResourceClaim and Pod: %s", err)
	}

}

func deployClusterConfig(ctx context.Context, t *check.Test) error {
	clientV2alpha1 := t.Context().K8sClient().CiliumClientset.CiliumV2alpha1()
	clientCoreV1 := t.Context().K8sClient().Clientset.CoreV1()

	clusterConfig := &v2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: nDClusterConfigName},
		Spec: v2alpha1.CiliumNetworkDriverClusterConfigSpec{
			Spec: v2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DriverName: nDName,
				DeviceManagerConfigs: &v2alpha1.CiliumNetworkDriverDeviceManagerConfig{
					Dummy: &v2alpha1.DummyDeviceManagerConfig{
						Enabled: true,
						Count:   nDNumDevicesPerNode,
					},
				},
				Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
					{
						PoolName: nDPoolName,
						Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{
							DeviceManagers: []string{nDDummyDeviceManagerName},
						},
					},
				},
			},
		},
	}
	generatedClusterConfig, err := clientV2alpha1.CiliumNetworkDriverClusterConfigs().Create(ctx, clusterConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create CiliumNetworkDriverClusterConfig: %w", err)
	}

	return wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		nodes, err := clientCoreV1.Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		configs, err := clientV2alpha1.CiliumNetworkDriverNodeConfigs().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		// we should have a config for each node
		if len(configs.Items) == 0 ||
			len(configs.Items) != len(nodes.Items) {
			return false, nil
		}

		// For each node config, check the specs are ok
		for i := range configs.Items {
			if !configs.Items[i].Spec.DeepEqual(&generatedClusterConfig.Spec.Spec) {
				return false, fmt.Errorf("node config spec does not match cluster config spec for node %q",
					configs.Items[i].Name)
			}
		}
		return true, nil
	})
}

func deployDeviceClass(ctx context.Context, t *check.Test) error {
	_, err := t.Context().K8sClient().Clientset.ResourceV1().DeviceClasses().Create(ctx, &resourceapi.DeviceClass{
		ObjectMeta: metav1.ObjectMeta{Name: nDDeviceClassName},
		Spec: resourceapi.DeviceClassSpec{
			Selectors: []resourceapi.DeviceSelector{
				{CEL: &resourceapi.CELDeviceSelector{Expression: fmt.Sprintf("device.driver == %q", nDName)}},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create DeviceClass: %w", err)
	}

	return nil
}

func deployStaticIPResourceClaimAndPod(ctx context.Context, t *check.Test) error {
	const (
		ipv4Addr = "100.64.0.1/32"
		ipv6Addr = "fd00::1/128"
	)

	rawParams, err := json.Marshal(map[string]string{
		"ipv4Addr": ipv4Addr,
		"ipv6Addr": ipv6Addr,
	})
	if err != nil {
		return fmt.Errorf("marshal static IP device config: %w", err)
	}

	t.Infof("Deploying pod %s and claim %s", nDStaticIPPodName, nDStaticIPClaimName)
	if err := deployResourceClaimAndPod(ctx, t, nDStaticIPClaimName, nDStaticIPPodName, rawParams); err != nil {
		return err
	}

	t.Info("Waiting for pod to be ready")
	if err := waitForNetworkDriverPodReady(ctx, t, nDStaticIPPodName); err != nil {
		return fmt.Errorf("wait for static IP pod ready: %w", err)
	}

	t.Info("Waiting resource claim status update")
	return waitForNetworkDriverClaimStatus(ctx, t, nDStaticIPClaimName, expectedNetworkDriverDeviceStatus{
		config: ndtypes.DeviceConfig{
			IPv4Addr: netip.MustParsePrefix(ipv4Addr),
			IPv6Addr: netip.MustParsePrefix(ipv6Addr),
		}, managerType: ndtypes.DeviceManagerTypeDummy})
}

func deployResourceIPPool(ctx context.Context, t *check.Test) error {
	_, err := t.Context().K8sClient().CiliumClientset.CiliumV2alpha1().CiliumResourceIPPools().Create(ctx, &v2alpha1.CiliumResourceIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: nDIPPoolName},
		Spec: v2alpha1.ResourceIPPoolSpec{
			IPv4: &v2.IPv4PoolSpec{
				CIDRs:    []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("100.65.0.0/24"))},
				MaskSize: 32,
			},
			IPv6: &v2.IPv6PoolSpec{
				CIDRs:    []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("fd00:1::/120"))},
				MaskSize: 128,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create CiliumResourceIPPool: %w", err)
	}

	return nil
}

func deployIPPoolResourceClaimAndPod(ctx context.Context, t *check.Test) error {
	rawParams, err := json.Marshal(map[string]string{"ipPool": nDIPPoolName})
	if err != nil {
		return fmt.Errorf("marshal IP pool device config: %w", err)
	}

	if err := deployResourceClaimAndPod(ctx, t, nDIPPoolClaimName, nDIPPoolPodName, rawParams); err != nil {
		return err
	}
	if err := waitForNetworkDriverPodReady(ctx, t, nDIPPoolPodName); err != nil {
		return fmt.Errorf("wait for IP pool pod ready: %w", err)
	}

	return waitForNetworkDriverClaimStatus(ctx, t,
		nDIPPoolClaimName,
		expectedNetworkDriverDeviceStatus{
			config:      ndtypes.DeviceConfig{IPPool: nDIPPoolName},
			managerType: ndtypes.DeviceManagerTypeDummy},
	)

}

func checkResourceSlices(ctx context.Context, t *check.Test) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		nodes, err := t.Context().K8sClient().Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		resourceSlices, err := t.Context().K8sClient().Clientset.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		matching := map[string]resourceapi.ResourceSlice{}
		for _, slice := range resourceSlices.Items {
			spec := slice.Spec
			if spec.Driver != nDName ||
				spec.Pool.Name != nDPoolName ||
				spec.NodeName == nil {
				continue
			}
			nodeName := *spec.NodeName
			if _, ok := matching[nodeName]; ok {
				return false, fmt.Errorf("multiple resource slices for node %q", nodeName)
			}
			matching[nodeName] = slice
		}

		for _, node := range nodes.Items {
			rs, ok := matching[node.Name]
			if !ok {
				t.Logf("no resource slice found for node %q", node.Name)
				return false, nil
			}
			if len(rs.Spec.Devices) != nDNumDevicesPerNode {
				t.Logf("expected %d devices in resource slice for node %q, found %d", nDNumDevicesPerNode, node.Name, len(rs.Spec.Devices))
				return false, nil
			}
		}
		return true, nil
	})
}

func deployResourceClaimAndPod(ctx context.Context, t *check.Test, claimName, podName string, rawParams []byte) error {
	client := t.Context().K8sClient()
	ns := t.Context().Params().TestNamespace

	_, err := client.Clientset.ResourceV1().ResourceClaims(ns).Create(ctx, &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: claimName, Namespace: ns},
		Spec: resourceapi.ResourceClaimSpec{
			Devices: resourceapi.DeviceClaim{
				Requests: []resourceapi.DeviceRequest{
					{
						Name: nDClaimRequestName,
						Exactly: &resourceapi.ExactDeviceRequest{
							DeviceClassName: nDDeviceClassName,
						},
					},
				},
				Config: []resourceapi.DeviceClaimConfiguration{
					{
						Requests: []string{nDClaimRequestName},
						DeviceConfiguration: resourceapi.DeviceConfiguration{
							Opaque: &resourceapi.OpaqueDeviceConfiguration{
								Driver:     nDName,
								Parameters: runtime.RawExtension{Raw: rawParams},
							},
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create ResourceClaim: %w", err)
	}

	_, err = client.Clientset.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: ptr.To[int64](1),
			ResourceClaims: []corev1.PodResourceClaim{
				{Name: "net", ResourceClaimName: ptr.To(claimName)},
			},
			Containers: []corev1.Container{
				{
					Name:    "app",
					Image:   t.Context().Params().CurlImage,
					Command: []string{"/usr/bin/pause"},
					Resources: corev1.ResourceRequirements{
						Claims: []corev1.ResourceClaim{{Name: "net", Request: nDClaimRequestName}},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create Pod: %w", err)
	}

	return nil
}

func cleanupNetworkDriverResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient()
	ns := t.Context().Params().TestNamespace
	check.DeleteK8sResourceWithWait(ctx, t, client.Clientset.CoreV1().Pods(ns), nDIPPoolPodName)
	check.DeleteK8sResourceWithWait(ctx, t, client.Clientset.CoreV1().Pods(ns), nDStaticIPPodName)
	check.DeleteK8sResourceWithWait(ctx, t, client.Clientset.ResourceV1().ResourceClaims(ns), nDIPPoolClaimName)
	check.DeleteK8sResourceWithWait(ctx, t, client.Clientset.ResourceV1().ResourceClaims(ns), nDStaticIPClaimName)
	check.DeleteK8sResourceWithWait(ctx, t, client.CiliumClientset.CiliumV2alpha1().CiliumResourceIPPools(), nDIPPoolName)
	check.DeleteK8sResourceWithWait(ctx, t, client.Clientset.ResourceV1().DeviceClasses(), nDDeviceClassName)
	check.DeleteK8sResourceWithWait(ctx, t, client.CiliumClientset.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs(), nDClusterConfigName)
}

func waitForNetworkDriverPodReady(ctx context.Context, t *check.Test, podName string) error {
	client := t.Context().K8sClient().Clientset.CoreV1().Pods(t.Context().Params().TestNamespace)

	return wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		pod, err := client.Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

func waitForNetworkDriverClaimStatus(ctx context.Context, t *check.Test, claimName string, expected expectedNetworkDriverDeviceStatus) error {
	namespace := t.Context().Params().TestNamespace
	client := t.Context().K8sClient().Clientset.ResourceV1().ResourceClaims(namespace)

	return wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
		claim, err := client.Get(ctx, claimName, metav1.GetOptions{})
		if err != nil {
			t.Logf("cannot get ResourceClaim %q: %w", claimName, err)
			return false, nil
		}
		devices := claim.Status.Devices
		if len(devices) == 0 {
			t.Logf("No devices status for ResourceClaim %q", claimName)
			return false, nil
		}

		for _, status := range devices {
			if err := validateNetworkDriverDeviceStatus(status, expected); err != nil {
				t.Logf("ResourceClaim %q status not ready: %s", claimName, err)
				return false, nil
			}
		}

		return true, nil
	})
}

type expectedNetworkDriverDeviceStatus struct {
	config      ndtypes.DeviceConfig
	managerType ndtypes.DeviceManagerType
}

func validateNetworkDriverDeviceStatus(status resourceapi.AllocatedDeviceStatus, expected expectedNetworkDriverDeviceStatus) error {
	// This is not the status of one of our devices.
	if status.Driver != nDName || status.Pool != nDPoolName {
		return nil
	}

	// Device name
	if status.Device == "" {
		return fmt.Errorf("missing device name")
	}

	// Conditions
	if !allocatedDeviceReady(status.Conditions) {
		return fmt.Errorf("allocated device is not ready")
	}

	// Network data
	if status.NetworkData == nil {
		return fmt.Errorf("missing network data")
	}
	if status.NetworkData.InterfaceName != status.Device {
		return fmt.Errorf("unexpected interface name %q for device %q", status.NetworkData.InterfaceName, status.Device)
	}
	if len(status.NetworkData.IPs) != 2 {
		return fmt.Errorf("expected 2 network data IPs, found %d", len(status.NetworkData.IPs))
	}
	// if we now the exact value of the expected IPv4 address, we can validate it against the network data
	if expected.config.IPv4Addr.IsValid() {
		if !slices.Contains(status.NetworkData.IPs, expected.config.IPv4Addr.String()) {
			return fmt.Errorf("missing expected IPv4 address %q in network data", expected.config.IPv4Addr.String())
		}
	}
	if expected.config.IPv6Addr.IsValid() {
		if !slices.Contains(status.NetworkData.IPs, expected.config.IPv6Addr.String()) {
			return fmt.Errorf("missing expected IPv6 address %q in network data", expected.config.IPv6Addr.String())
		}
	}

	// Data
	if status.Data == nil || len(status.Data.Raw) == 0 {
		return fmt.Errorf("missing serialized device data")
	}
	var serialized ndtypes.SerializedDevice
	if err := json.Unmarshal(status.Data.Raw, &serialized); err != nil {
		return fmt.Errorf("unmarshal serialized device data: %w", err)
	}
	if serialized.Manager != expected.managerType {
		return fmt.Errorf("unexpected device manager %q", serialized.Manager)
	}
	if len(serialized.Dev) == 0 {
		return fmt.Errorf("missing serialized device")
	}
	// Config validation
	cfg := serialized.Config
	if cfg.IPPool != expected.config.IPPool {
		return fmt.Errorf("unexpected serialized IP pool %q", cfg.IPPool)
	}
	// we can validate addresses
	if cfg.IPPool == "" {
		if cfg.IPv4Addr != expected.config.IPv4Addr {
			return fmt.Errorf("unexpected serialized IPv4 address %q", cfg.IPv4Addr)
		}
		if cfg.IPv6Addr != expected.config.IPv6Addr {
			return fmt.Errorf("unexpected serialized IPv6 address %q", cfg.IPv6Addr)
		}
	}
	return nil
}

func allocatedDeviceReady(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == string(corev1.PodReady) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
