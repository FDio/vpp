/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Guards the Pad1 off-by-one fix in the IPv6 Hop-by-Hop option walker,
 * exercised via the public ip6_hbh_get_option(). */

#include <vlib/vlib.h>
#include <vnet/ip/ip6_hop_by_hop.h>

/* RFC 4782 Quick-Start request option (Defensics IPv6 test #3145). */
#define HBH_OPT_QUICK_START 0x26

typedef struct
{
  const char *name;
  u8 *data;
  u32 data_len;
  u8 search;
  u32 expect_offset;
  u8 expect_present;
  u8 expect_type;
  u8 expect_length;
} hbh_opt_test_t;

/* Each buffer is a full HbH header (byte 0 next-proto, byte 1 Hdr Ext Len),
 * 16 bytes = one 8-octet unit, so byte 1 is 1. */

/* Pad1 before Quick-Start: the core regression (odd offset). */
static u8 tc_pad1_then_qs[16] = {
  IP_PROTOCOL_ICMP6, 1,
  0x00,					/* Pad1 */
  HBH_OPT_QUICK_START, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x03, 0x00, 0x00, 0x00		/* PadN tail pad */
};

static u8 tc_pad1_between[16] = {
  IP_PROTOCOL_ICMP6, 1,
  0x1e, 0x00,				/* unknown option */
  0x00,					/* Pad1 */
  HBH_OPT_QUICK_START, 0x06,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
  0x01, 0x01, 0x00
};

/* PadN (untouched path) then Quick-Start: regression guard. */
static u8 tc_padn_then_qs[16] = {
  IP_PROTOCOL_ICMP6, 1,
  0x01, 0x04, 0x00, 0x00, 0x00, 0x00,	/* PadN */
  HBH_OPT_QUICK_START, 0x06,
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26
};

static u8 tc_qs_first[16] = {
  IP_PROTOCOL_ICMP6, 1,
  HBH_OPT_QUICK_START, 0x06,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x01, 0x03, 0x00, 0x00, 0x00, 0x00
};

static hbh_opt_test_t hbh_opt_tests[] = {
  {
    .name = "pad1-then-quickstart",
    .data = tc_pad1_then_qs,
    .data_len = sizeof (tc_pad1_then_qs),
    .search = HBH_OPT_QUICK_START,
    .expect_present = 1,
    .expect_offset = 3,
    .expect_type = HBH_OPT_QUICK_START,
    .expect_length = 6,
  },
  {
    .name = "pad1-between-options",
    .data = tc_pad1_between,
    .data_len = sizeof (tc_pad1_between),
    .search = HBH_OPT_QUICK_START,
    .expect_present = 1,
    .expect_offset = 5,
    .expect_type = HBH_OPT_QUICK_START,
    .expect_length = 6,
  },
  {
    .name = "padn-then-quickstart",
    .data = tc_padn_then_qs,
    .data_len = sizeof (tc_padn_then_qs),
    .search = HBH_OPT_QUICK_START,
    .expect_present = 1,
    .expect_offset = 8,
    .expect_type = HBH_OPT_QUICK_START,
    .expect_length = 6,
  },
  {
    .name = "quickstart-first",
    .data = tc_qs_first,
    .data_len = sizeof (tc_qs_first),
    .search = HBH_OPT_QUICK_START,
    .expect_present = 1,
    .expect_offset = 2,
    .expect_type = HBH_OPT_QUICK_START,
    .expect_length = 6,
  },
  {
    /* Absent option behind a Pad1: walker must terminate, return NULL. */
    .name = "pad1-option-absent",
    .data = tc_pad1_then_qs,
    .data_len = sizeof (tc_pad1_then_qs),
    .search = 0x05,
    .expect_present = 0,
  },
};

static clib_error_t *
test_ip6_hbh_options_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  u32 i;

  for (i = 0; i < ARRAY_LEN (hbh_opt_tests); i++)
    {
      hbh_opt_test_t *tc = &hbh_opt_tests[i];
      ip6_hop_by_hop_header_t *hbh = (ip6_hop_by_hop_header_t *) tc->data;
      ip6_hop_by_hop_option_t *opt;

      opt = ip6_hbh_get_option (hbh, tc->search);

      if (!tc->expect_present)
	{
	  if (opt != NULL)
	    return clib_error_create (
	      "test '%s' failed: expected option 0x%02x absent, "
	      "got match at offset %u",
	      tc->name, tc->search, (u32) ((u8 *) opt - tc->data));
	  continue;
	}

      if (opt == NULL)
	return clib_error_create (
	  "test '%s' failed: option 0x%02x not found (Pad1 off-by-one?)",
	  tc->name, tc->search);

      if ((u8 *) opt != tc->data + tc->expect_offset)
	return clib_error_create (
	  "test '%s' failed: option 0x%02x found at offset %u, expected %u",
	  tc->name, tc->search, (u32) ((u8 *) opt - tc->data),
	  tc->expect_offset);

      if (opt->type != tc->expect_type || opt->length != tc->expect_length)
	return clib_error_create (
	  "test '%s' failed: found option type/len %u/%u, expected %u/%u",
	  tc->name, opt->type, opt->length, tc->expect_type,
	  tc->expect_length);
    }

  vlib_cli_output (vm, "All %u IPv6 hop-by-hop option tests passed",
		   ARRAY_LEN (hbh_opt_tests));
  return 0;
}

VLIB_CLI_COMMAND (test_ip6_hbh_options_command, static) = {
  .path = "test ip6-hbh-options",
  .short_help = "Coverage test for IPv6 hop-by-hop Pad1 option walking",
  .function = test_ip6_hbh_options_command_fn,
};
