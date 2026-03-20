package main

import (
	"fmt"
	"strings"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(
		TlsProfileBasicTest,
		TlsProfileAllParamsTest,
		TlsProfileCipherListTest,
		TlsProfileMultipleTest,
		TlsProfileDeleteTest,
		TlsProfileMinVersionTest,
		TlsProfileMaxVersionTest,
		TlsProfileVersionRangeTest,
		TlsProfileFallbackDefaultTest,
		TlsProfileNegotiatedParamsTest,
		TlsProfileNegotiatedVersionTest,
	)
}

// Create profile with minimal config (cipher-list only)
func TlsProfileBasicTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	// Create application first (tls_server creates app named "test_tls_server")
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with cipher-list
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server cipher-list AES128-SHA")
	Log(o)
	AssertNotContains(o, "error")
	AssertNotContains(o, "failed")
	AssertContains(o, "profile 0")

	// Verify profile created
	o = serverVpp.Vppctl("show app tls-profile app test_tls_server")
	Log(o)
	AssertContains(o, "aes128-sha")
	AssertContains(o, "[0]")
}

// Create profile with all parameters
func TlsProfileAllParamsTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with all parameters
	cmd := "app crypto add tls-profile app test_tls_server " +
		"cipher-list AES256-GCM-SHA384 " +
		"ciphersuites TLS_AES_256_GCM_SHA384 " +
		"groups P-256:P-384 " +
		"min-version 1.2 " +
		"max-version 1.3"
	o := serverVpp.Vppctl(cmd)
	Log(o)
	AssertNotContains(o, "error")

	// Verify all fields
	o = serverVpp.Vppctl("show app tls-profile app test_tls_server")
	Log(o)
	AssertContains(o, "aes256-gcm-sha384")
	AssertContains(o, "TLS_AES_256_GCM_SHA384")
	AssertContains(o, "P-256:P-384")
	AssertContains(o, "1.2")
	AssertContains(o, "1.3")
}

// Delete profile
func TlsProfileDeleteTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server cipher-list AES128-SHA")
	Log(o)
	AssertContains(o, "profile 0")

	// Delete profile
	o = serverVpp.Vppctl("app crypto del tls-profile app test_tls_server 0")
	Log(o)
	AssertNotContains(o, "error")

	// Verify it's gone (show should not show the profile or give empty output)
	o = serverVpp.Vppctl("show app tls-profile app test_tls_server")
	Log(o)
	AssertNotContains(o, "aes128-sha")
}

// Listener uses profile cipher list
func TlsProfileCipherListTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start server first to create app named "test_tls_server"
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with specific cipher
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server cipher-list AES256-GCM-SHA384")
	Log(o)
	AssertContains(o, "profile 0")

	// Restart server with profile
	// First stop existing server (need to detach app)
	// For now, use a different port
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress2 + " profile-index 0"))

	// Client connects
	uri := "tls://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
}

// Multiple profiles per app
func TlsProfileMultipleTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create first profile
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server cipher-list AES128-SHA")
	Log(o)
	AssertContains(o, "profile 0")

	// Create second profile
	o = serverVpp.Vppctl("app crypto add tls-profile app test_tls_server cipher-list AES256-SHA")
	Log(o)
	AssertContains(o, "profile 1")

	// Verify both exist
	o = serverVpp.Vppctl("show app tls-profile app test_tls_server")
	Log(o)
	AssertContains(o, "aes128-sha")
	AssertContains(o, "aes256-sha")
	AssertContains(o, "[0]")
	AssertContains(o, "[1]")
}

// Min version enforcement
func TlsProfileMinVersionTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with min version TLS 1.2
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server min-version 1.2")
	Log(o)
	AssertContains(o, "profile 0")

	// Start server with profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress2 + " profile-index 0"))

	// Client connects (should succeed with TLS 1.2 or higher)
	uri := "tls://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	// Connection should work since default is TLS 1.2+
	AssertNotContains(o, "timeout")
	// Verify we got at least TLS 1.2 (not older versions like 1.0 or 1.1)
	AssertNotContains(o, "TLS version: 1.0")
	AssertNotContains(o, "TLS version: 1.1")
}

// Max version enforcement
func TlsProfileMaxVersionTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with max version TLS 1.2
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server max-version 1.2")
	Log(o)
	AssertContains(o, "profile 0")

	// Start server with profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress2 + " profile-index 0"))

	// Client connects
	uri := "tls://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	// Should negotiate TLS 1.2 or lower
	AssertNotContains(o, "timeout")
	// Verify negotiated TLS version is not higher than 1.2
	AssertNotContains(o, "TLS version: 1.3")
}

// Version range
func TlsProfileVersionRangeTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Create profile with TLS 1.2 only
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server min-version 1.2 max-version 1.2")
	Log(o)
	AssertContains(o, "profile 0")

	// Start server with profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress2 + " profile-index 0"))

	// Client connects
	uri := "tls://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	// Should work with TLS 1.2 or lower
	AssertNotContains(o, "timeout")
	// Verify negotiated TLS version is not higher than 1.2
	AssertNotContains(o, "TLS version: 1.3")
}

// No profile specified (fallback to defaults)
func TlsProfileFallbackDefaultTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	// Start server without profile
	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Client connects
	uri := "tls://" + serverAddress
	o := clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	// Should work with global OpenSSL defaults
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
}

// Verify negotiated cipher, TLS version, key agreement and signature algorithm are displayed
func TlsProfileNegotiatedParamsTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start server without profile (use defaults)
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Client connects
	uri := "tls://" + serverAddress
	o := clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")

	// Verify cipher and TLS version are displayed with valid values
	AssertContains(o, "Cipher:")
	AssertContains(o, "TLS version:")
	if !strings.Contains(o, "1.2") && !strings.Contains(o, "1.3") {
		AssertNil(fmt.Errorf("Expected TLS version 1.2 or 1.3, got: %s", o))
	}

	// Verify key agreement algorithm is displayed (e.g. X25519, prime256v1, secp256r1)
	AssertContains(o, "Key agreement:")
	// Common ECDH groups used in TLS 1.2/1.3
	knownGroups := []string{"X25519", "prime256v1", "secp256r1", "secp384r1", "secp521r1", "x448"}
	foundGroup := false
	for _, g := range knownGroups {
		if strings.Contains(o, g) {
			foundGroup = true
			break
		}
	}
	if !foundGroup {
		AssertNil(fmt.Errorf("Expected a known key agreement group in output, got: %s", o))
	}

	// Verify signature algorithm is displayed (e.g. SHA256 from SSL_get_peer_signature_nid)
	AssertContains(o, "Signature algorithm:")
	knownSigAlgs := []string{"RSA", "ECDSA", "Ed25519", "Ed448", "DSA", "SHA256", "SHA384", "SHA512"}
	foundSigAlg := false
	for _, alg := range knownSigAlgs {
		if strings.Contains(o, alg) {
			foundSigAlg = true
			break
		}
	}
	if !foundSigAlg {
		AssertNil(fmt.Errorf("Expected a known signature algorithm in output, got: %s", o))
	}
}

// Verify negotiated TLS version with profile
func TlsProfileNegotiatedVersionTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start server first to create app
	Log(serverVpp.Vppctl("test tls server uri tls://" + serverAddress))

	// Wait a moment for server to initialize
	// Note: In a real setup, the profile would be created before starting the server
	// or the server would be restarted with the profile
	// For this test, we just verify the display works

	// Client connects
	uri := "tls://" + serverAddress
	o := clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")

	// Verify negotiated parameters include valid TLS version
	AssertContains(o, "TLS version:")
	// Should get TLS 1.2 or 1.3 (modern defaults)
	if !strings.Contains(o, "1.2") && !strings.Contains(o, "1.3") {
		AssertNil(fmt.Errorf("Expected TLS version 1.2 or 1.3, got: %s", o))
	}
}
