/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <hs_apps/builtin_echo/echo_test.h>

echo_test_main_t echo_test_main;

static int
et_tcp_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  return vnet_listen (args);
}

static echo_test_proto_vft_t echo_test_tcp = {
  .listen = et_tcp_listen,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_TCP, echo_test_tcp);

static int
et_udp_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  return vnet_listen (args);
}

static echo_test_proto_vft_t echo_test_udp = {
  .listen = et_udp_listen,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_UDP, echo_test_udp);

static int
et_tls_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  int rv = vnet_listen (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static echo_test_proto_vft_t echo_test_tls = {
  .listen = et_tls_listen,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_TLS, echo_test_tls);

static int
et_quic_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  int rv = vnet_listen (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static echo_test_proto_vft_t echo_test_quic = {
  .listen = et_quic_listen,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_QUIC, echo_test_quic);
