#ifndef QUIC_CRYPTO
#define QUIC_CRYPTO

#include <vnet/session/application_interface.h>

#include <vppinfra/lock.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/bihash_16_8.h>

#include <quicly.h>

extern ptls_cipher_suite_t *vpp_crypto_cipher_suites[];

#endif