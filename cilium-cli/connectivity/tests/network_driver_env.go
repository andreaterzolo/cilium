// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// networkDriverScenarioEnv holds the resources and cleanup state owned by one scenario.
type networkDriverScenarioEnv struct {
	t          *check.Test
	finalizers []func(context.Context) error
}

func newNetworkDriverScenarioEnv(t *check.Test) *networkDriverScenarioEnv {
	return &networkDriverScenarioEnv{t: t}
}

// cleanup deletes everything the scenario created, newest first, and waits
// for the scenario's pods to be gone so devices are free for the next one.
func (e *networkDriverScenarioEnv) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), networkDriverTimeout)
	defer cancel()

	for _, finalize := range slices.Backward(e.finalizers) {
		if err := finalize(ctx); err != nil && !k8serrors.IsNotFound(err) {
			e.t.Infof("Network driver cleanup: %s", err)
		}
	}
	if err := e.waitPodsGone(ctx); err != nil {
		e.t.Infof("Network driver cleanup: %s", err)
	}
}

func (e *networkDriverScenarioEnv) testNamespace() string {
	return e.t.Context().Params().TestNamespace
}

func (e *networkDriverScenarioEnv) ipv4Enabled() bool {
	ipv4, ok := e.t.Context().Feature(features.IPv4)
	if !ok {
		e.t.Fatalf("Detecting IPv4 feature")
	}
	return ipv4.Enabled
}

func (e *networkDriverScenarioEnv) ipv6Enabled() bool {
	ipv6, ok := e.t.Context().Feature(features.IPv6)
	if !ok {
		e.t.Fatalf("Detecting IPv6 feature")
	}
	return ipv6.Enabled
}

func (e *networkDriverScenarioEnv) waitPodsGone(ctx context.Context) error {
	return wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			pods, err := e.t.Context().K8sClient().Clientset.CoreV1().Pods(e.testNamespace()).List(ctx,
				metav1.ListOptions{LabelSelector: "app=" + networkDriverTestName})
			return err == nil && len(pods.Items) == 0, nil
		})
}

// claimOpaqueParams is the opaque config of one device request, as the driver reads it.
type claimOpaqueParams struct {
	PodIfName string `json:"podIfName,omitempty"`
	IPv4Addr  string `json:"ipv4Addr,omitempty"`
	IPv6Addr  string `json:"ipv6Addr,omitempty"`
}

// createPod creates a pod with one single-device claim per entry in claims. It returns the pod name.
func (e *networkDriverScenarioEnv) createPod(ctx context.Context, claims ...claimOpaqueParams) string {
	client := e.t.Context().K8sClient().Clientset

	var podClaims []corev1.PodResourceClaim
	for i, claim := range claims {
		raw, err := json.Marshal(claim)
		if err != nil {
			e.t.Fatalf("Encoding claim config: %s", err)
		}
		tmpl := &resourceapi.ResourceClaimTemplate{
			ObjectMeta: metav1.ObjectMeta{GenerateName: networkDriverTestName, Namespace: e.testNamespace()},
			Spec: resourceapi.ResourceClaimTemplateSpec{Spec: resourceapi.ResourceClaimSpec{
				Devices: resourceapi.DeviceClaim{
					Requests: []resourceapi.DeviceRequest{{
						Name:    "dev",
						Exactly: &resourceapi.ExactDeviceRequest{DeviceClassName: networkDriverDeviceClassName},
					}},
					Config: []resourceapi.DeviceClaimConfiguration{{
						Requests: []string{"dev"},
						DeviceConfiguration: resourceapi.DeviceConfiguration{
							Opaque: &resourceapi.OpaqueDeviceConfiguration{
								Driver:     networkDriverName,
								Parameters: runtime.RawExtension{Raw: raw},
							},
						},
					}},
				},
			}},
		}
		createdTemplate, err := client.ResourceV1().ResourceClaimTemplates(e.testNamespace()).Create(ctx, tmpl, metav1.CreateOptions{})
		if err != nil {
			e.t.Fatalf("Creating ResourceClaimTemplate: %s", err)
		}
		tmplName := createdTemplate.Name
		e.finalizers = append(e.finalizers, func(ctx context.Context) error {
			return client.ResourceV1().ResourceClaimTemplates(e.testNamespace()).Delete(ctx, tmplName, metav1.DeleteOptions{})
		})
		podClaims = append(podClaims, corev1.PodResourceClaim{
			Name:                      fmt.Sprintf("c%d", i),
			ResourceClaimTemplateName: ptr.To(tmplName),
		})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: networkDriverTestName,
			Namespace:    e.testNamespace(),
			Labels:       map[string]string{"app": networkDriverTestName},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: ptr.To[int64](1),
			Containers: []corev1.Container{{
				Name:    "c",
				Image:   e.t.Context().Params().CurlImage,
				Command: []string{"/usr/bin/pause"},
			}},
			ResourceClaims: podClaims,
		},
	}
	createdPod, err := client.CoreV1().Pods(e.testNamespace()).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		e.t.Fatalf("Creating pod: %s", err)
	}
	name := createdPod.Name
	e.finalizers = append(e.finalizers, func(ctx context.Context) error {
		return client.CoreV1().Pods(e.testNamespace()).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	})
	return name
}

// ndDeviceStatus is what the driver is expected to report for one device in
// ResourceClaim.status.devices.
type ndDeviceStatus struct {
	InterfaceName string
	IPs           []string
}

// expectClaimStatus checks the driver's device status entries of the pod
// claim podClaim (c0, c1, ...) match want, in any order. Address families
// the driver has disabled are dropped from want: the driver does not report
// them.
func (e *networkDriverScenarioEnv) expectClaimStatus(ctx context.Context, pod, podClaim string, want ...ndDeviceStatus) {
	for i := range want {
		want[i].IPs = slices.DeleteFunc(slices.Clone(want[i].IPs), func(ip string) bool {
			v6 := strings.Contains(ip, ":")
			return (v6 && !e.ipv6Enabled()) || (!v6 && !e.ipv4Enabled())
		})
		slices.Sort(want[i].IPs)
	}
	key := func(d ndDeviceStatus) string { return d.InterfaceName + "=" + strings.Join(d.IPs, ",") }
	wantKeys := make([]string, 0, len(want))
	for _, w := range want {
		wantKeys = append(wantKeys, key(w))
	}
	slices.Sort(wantKeys)

	client := e.t.Context().K8sClient().Clientset
	var got []string
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			p, err := client.CoreV1().Pods(e.testNamespace()).Get(ctx, pod, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			var claimName string
			for _, s := range p.Status.ResourceClaimStatuses {
				if s.Name == podClaim && s.ResourceClaimName != nil {
					claimName = *s.ResourceClaimName
				}
			}
			if claimName == "" {
				return false, nil
			}
			c, err := client.ResourceV1().ResourceClaims(e.testNamespace()).Get(ctx, claimName, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			got = got[:0]
			for _, d := range c.Status.Devices {
				if d.Driver != networkDriverName {
					continue
				}
				st := ndDeviceStatus{}
				if d.NetworkData != nil {
					st.InterfaceName = d.NetworkData.InterfaceName
					st.IPs = slices.Clone(d.NetworkData.IPs)
					slices.Sort(st.IPs)
				}
				got = append(got, key(st))
			}
			slices.Sort(got)
			return slices.Equal(got, wantKeys), nil
		})
	if err != nil {
		e.t.Fatalf("Pod %s claim %s device status = %v, want %v", pod, podClaim, got, wantKeys)
	}
}

func (e *networkDriverScenarioEnv) waitRunning(ctx context.Context, name string) {
	if err := wait.PollUntilContextTimeout(
		ctx,
		networkDriverPollInterval,
		networkDriverTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			p, err := e.t.Context().K8sClient().Clientset.
				CoreV1().Pods(e.testNamespace()).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			return p.Status.Phase == corev1.PodRunning, nil
		}); err != nil {
		e.t.Fatalf("Pod %s not Running: %s", name, err)
	}
}

func (e *networkDriverScenarioEnv) deletePod(ctx context.Context, name string) {
	err := e.t.Context().K8sClient().Clientset.CoreV1().Pods(e.testNamespace()).Delete(ctx, name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	if err != nil && !k8serrors.IsNotFound(err) {
		e.t.Fatalf("Deleting pod %s: %s", name, err)
	}
	err = wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			_, err := e.t.Context().K8sClient().Clientset.CoreV1().Pods(e.testNamespace()).Get(ctx, name, metav1.GetOptions{})
			return k8serrors.IsNotFound(err), nil
		})
	if err != nil {
		e.t.Fatalf("Pod %s not deleted: %s", name, err)
	}
}

func (e *networkDriverScenarioEnv) multipleClaimConfigs() (net1, net2 claimOpaqueParams) {
	net1.PodIfName = "net1"
	net2.PodIfName = "net2"

	if e.ipv4Enabled() {
		net1.IPv4Addr = "192.0.2.31/24"
		net2.IPv4Addr = "198.51.100.31/24"
	}
	if e.ipv6Enabled() {
		net1.IPv6Addr = "2001:db8::31/64"
		net2.IPv6Addr = "2001:db8:1::31/64"
	}
	return net1, net2
}

// nonEmpty returns its non-empty arguments.
func nonEmpty(ss ...string) []string {
	return slices.DeleteFunc(ss, func(s string) bool { return s == "" })
}
