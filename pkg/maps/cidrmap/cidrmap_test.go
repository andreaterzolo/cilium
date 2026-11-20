// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidrmap

import (
	"testing"
	"unsafe"
)

func TestCIDRKeySizes(t *testing.T) {
	if got := unsafe.Sizeof(cidrKey4{}); got != 8 {
		t.Fatalf("IPv4 CIDR key is %d bytes, want 8", got)
	}
	if got := unsafe.Sizeof(cidrKey6{}); got != 20 {
		t.Fatalf("IPv6 CIDR key is %d bytes, want 20", got)
	}
}
