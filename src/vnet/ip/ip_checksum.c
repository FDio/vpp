/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip4/ip_checksum.c: ip/tcp/udp checksums */

#include <vnet/ip/ip.h>

static ip_csum_t
_ip_incremental_checksum (ip_csum_t sum, void *_data, uword n_bytes)
{
  uword data = pointer_to_uword (_data);
  ip_csum_t sum0, sum1;

  sum0 = 0;
  sum1 = sum;

  /*
   * Align pointer to 64 bits. The ip checksum is a 16-bit
   * one's complememt sum. It's impractical to optimize
   * the calculation if the incoming address is odd.
   */
#define _(t)					\
do {						\
  if (n_bytes >= sizeof (t)			\
      && sizeof (t) < sizeof (ip_csum_t)	\
      && (data % (2 * sizeof (t))) != 0)	\
    {						\
      sum0 += * uword_to_pointer (data, t *);	\
      data += sizeof (t);			\
      n_bytes -= sizeof (t);			\
    }						\
} while (0)

  if (PREDICT_TRUE ((data & 1) == 0))
    {
      _(u16);
      if (BITS (ip_csum_t) > 32)
	_(u32);
    }
#undef _

  {
    ip_csum_t *d = uword_to_pointer (data, ip_csum_t *);

    while (n_bytes >= 2 * sizeof (d[0]))
      {
	sum0 = ip_csum_with_carry (sum0, d[0]);
	sum1 = ip_csum_with_carry (sum1, d[1]);
	d += 2;
	n_bytes -= 2 * sizeof (d[0]);
      }

    data = pointer_to_uword (d);
  }

#define _(t)								\
do {									\
  if (n_bytes >= sizeof (t) && sizeof (t) <= sizeof (ip_csum_t))	\
    {									\
      sum0 = ip_csum_with_carry (sum0, * uword_to_pointer (data, t *));	\
      data += sizeof (t);						\
      n_bytes -= sizeof (t);						\
    }									\
} while (0)

  if (BITS (ip_csum_t) > 32)
    _(u64);
  _(u32);
  _(u16);
  _(u8);

#undef _

  /* Combine even and odd sums. */
  sum0 = ip_csum_with_carry (sum0, sum1);

  return sum0;
}

/*
 * Note: the tcp / udp checksum calculation is performance critical
 * [e.g. when NIC h/w offload is not available],
 * so it's worth producing architecture-dependent code.
 *
 * ip_incremental_checksum() is an always-inlined static
 * function which uses the function pointer we set up in
 * ip_checksum_init().
 */

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword);

clib_error_t *
ip_checksum_init (vlib_main_t *vm)
{
  vnet_incremental_checksum_fp = _ip_incremental_checksum;
  return 0;
}

VLIB_INIT_FUNCTION (ip_checksum_init);

#if CLIB_DEBUG > 0

static const char test_pkt[] = {
  0x45, 0x00, 0x00, 0x3c, 0x5d, 0x6f, 0x40, 0x00,
  0x40, 0x06, 0x3f, 0x6b, 0x0a, 0x76, 0x72, 0x44,
  0x0a, 0x56, 0x16, 0xd2,
};

static clib_error_t *
test_ip_checksum_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u16 csum;
  ip4_header_t *hp;
  u8 *align_test = 0;
  int offset;

  vec_validate (align_test, ARRAY_LEN (test_pkt) + 7);

  for (offset = 0; offset < 8; offset++)
    {
      memcpy (align_test + offset, test_pkt, ARRAY_LEN (test_pkt));

      hp = (ip4_header_t *) (align_test + offset);
      csum = ip4_header_checksum (hp);

      vlib_cli_output (vm, "offset %d checksum %u expected result 27455",
		       offset, (u32) csum);
    }

  return 0;
}

VLIB_CLI_COMMAND (test_checksum, static) =
{
  .path = "test ip checksum",
  .short_help = "test ip checksum",
  .function = test_ip_checksum_fn,
};

#endif /* CLIB_DEBUG */
