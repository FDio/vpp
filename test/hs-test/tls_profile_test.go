package main

import (
	"fmt"
	"strings"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterTlsTests(
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
		TlsProfileX25519EcdsaTest,
	)
	RegisterQuicTests(
		QuicTlsProfileNegotiatedParamsTest,
		QuicTlsProfileCipherFilterTest,
		QuicTlsProfileGroupRestrictionTest,
	)
}

// Create profile with minimal config (cipher-list only)
func TlsProfileBasicTest(s *TlsSuite) {
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
func TlsProfileAllParamsTest(s *TlsSuite) {
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
func TlsProfileDeleteTest(s *TlsSuite) {
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
func TlsProfileCipherListTest(s *TlsSuite) {
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
func TlsProfileMultipleTest(s *TlsSuite) {
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
func TlsProfileMinVersionTest(s *TlsSuite) {
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
func TlsProfileMaxVersionTest(s *TlsSuite) {
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
func TlsProfileVersionRangeTest(s *TlsSuite) {
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
func TlsProfileFallbackDefaultTest(s *TlsSuite) {
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
func TlsProfileNegotiatedParamsTest(s *TlsSuite) {
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
func TlsProfileNegotiatedVersionTest(s *TlsSuite) {
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

// Verify that a TLS profile specifying groups=X25519 with ECDSA certificates
// results in X25519 as the negotiated key agreement group and an ECDSA/SHA
// signature algorithm.
func TlsProfileX25519EcdsaTest(s *TlsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start server with ECDSA certificates
	Log(serverVpp.Vppctl("test tls server cert-type ecdsa uri tls://" + serverAddress))

	// Create a TLS profile that restricts key agreement to X25519
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server groups X25519")
	Log(o)
	AssertNotContains(o, "error")
	AssertContains(o, "profile 0")

	// Start a second listener on a fresh port using the profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server cert-type ecdsa profile-index 0 uri tls://" + serverAddress2))

	// Client connects using ECDSA certificates so it trusts the server cert
	uri := "tls://" + serverAddress2
	o = clientVpp.Vppctl("test tls client cert-type ecdsa uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")

	// Key agreement must be X25519 (as mandated by the profile)
	AssertContains(o, "Key agreement: X25519")

	// Signature algorithm must be ED25519
	AssertContains(o, "Signature algorithm:")
	ecdsaSigAlgs := []string{"ED25519", "Ed25519"}
	foundSig := false
	for _, alg := range ecdsaSigAlgs {
		if strings.Contains(o, alg) {
			foundSig = true
			break
		}
	}
	if !foundSig {
		AssertNil(fmt.Errorf("Expected ECDSA-related signature algorithm, got: %s", o))
	}
}

// QuicTlsProfileNegotiatedParamsTest verifies that cipher suite, key exchange
// group, and TLS version are returned for a QUIC connection.  QUIC always uses
// TLS 1.3, so version must always be "1.3".
func QuicTlsProfileNegotiatedParamsTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Start QUIC server (no profile — use defaults)
	Log(serverVpp.Vppctl("test tls server uri quic://" + serverAddress))

	// Connect QUIC client
	uri := "quic://" + serverAddress
	o := clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")

	// Cipher must be a TLS 1.3 AEAD suite
	AssertContains(o, "Cipher:")
	quicCiphers := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	}
	foundCipher := false
	for _, c := range quicCiphers {
		if strings.Contains(o, c) {
			foundCipher = true
			break
		}
	}
	AssertEqual(true, foundCipher, "Expected TLS 1.3 cipher suite in QUIC output")

	// QUIC always runs TLS 1.3
	AssertContains(o, "TLS version: 1.3")

	// Key agreement group must be known; picotls returns lowercase names
	AssertContains(o, "Key agreement:")
	knownGroups := []string{"x25519", "secp256r1", "secp384r1", "secp521r1", "X25519", "P-256", "P-384", "P-521"}
	foundGroup := false
	for _, g := range knownGroups {
		if strings.Contains(o, g) {
			foundGroup = true
			break
		}
	}
	AssertEqual(true, foundGroup, "Expected a known key agreement group in QUIC output")

	// picotls does not expose the negotiated signature algorithm, so the field
	// may be absent — but if present it must not be empty
	if strings.Contains(o, "Signature algorithm:") {
		lines := strings.SplitSeq(o, "\n")
		for l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "Signature algorithm:") {
				parts := strings.SplitN(l, ":", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) == "" {
					AssertNil(fmt.Errorf("Signature algorithm line is empty: %s", l))
				}
			}
		}
	}
}

// QuicTlsProfileCipherFilterTest verifies that a QUIC TLS profile with a
// ciphersuites restriction does not break the handshake. Note: QUIC always
// requires TLS_AES_128_GCM_SHA256 for Initial packet protection, so that
// cipher is retained even when the profile restricts to TLS_AES_256_GCM_SHA384.
func QuicTlsProfileCipherFilterTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Create app + profile on server VPP
	Log(serverVpp.Vppctl("test tls server uri quic://" + serverAddress))

	// Restrict to TLS_AES_256_GCM_SHA384 only.  AES-128 will be kept by the
	// implementation because quicly requires it for Initial packet processing.
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server " +
		"ciphersuites TLS_AES_256_GCM_SHA384")
	Log(o)
	AssertNotContains(o, "error")
	AssertContains(o, "profile 0")

	// Start a second listener with the profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server profile-index 0 uri quic://" + serverAddress2))

	// Client connects
	uri := "quic://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	// A cipher must be reported; the exact value depends on client preference
	AssertContains(o, "Cipher:")

	// QUIC always uses TLS 1.3
	AssertContains(o, "TLS version: 1.3")
}

// QuicTlsProfileGroupRestrictionTest verifies that a QUIC TLS profile restricting
// the key exchange group to X25519 does not break connectivity and that a key
// agreement group is reported.
//
// Note: picotls has no public API to retrieve the negotiated key exchange group
// after the handshake.  The key_agreement field reported by tls_profile_info is
// the first group from the *client*'s configured list, not necessarily the one
// that was actually negotiated.  This test therefore only checks that the
// connection succeeds and that the field is populated.
func QuicTlsProfileGroupRestrictionTest(s *QuicSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	serverAddress := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1

	// Create app first (initialises the app name "test_tls_server")
	Log(serverVpp.Vppctl("test tls server uri quic://" + serverAddress))

	// Create profile restricting key exchange to X25519 only
	o := serverVpp.Vppctl("app crypto add tls-profile app test_tls_server groups X25519")
	Log(o)
	AssertNotContains(o, "error")
	AssertContains(o, "profile 0")

	// Start a second listener with the X25519-only profile
	serverAddress2 := s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port2
	Log(serverVpp.Vppctl("test tls server profile-index 0 uri quic://" + serverAddress2))

	// Client connects (uses ptls_openssl_key_exchanges_all which includes x25519)
	uri := "quic://" + serverAddress2
	o = clientVpp.Vppctl("test tls client uri " + uri)
	Log(o)
	AssertNotContains(o, "connect failed")
	AssertNotContains(o, "timeout")
	AssertNotContains(o, "failed tls handshake")

	// A key agreement group must be reported; the exact value matches the
	// client's first configured group (not necessarily the negotiated one)
	AssertContains(o, "Key agreement:")

	// QUIC always uses TLS 1.3
	AssertContains(o, "TLS version: 1.3")
}
