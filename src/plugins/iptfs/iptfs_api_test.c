/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * January 10 2020, Christian E. Hopps <chopps@labn.net>
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <iptfs/ipsec_iptfs.h>

#define __plugin_msg_base iptfs_api_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <iptfs/iptfs_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <iptfs/iptfs_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun /* define message structures */
#include <iptfs/iptfs_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <iptfs/iptfs_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <iptfs/iptfs_all_api_h.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} iptfs_api_test_main_t;

iptfs_api_test_main_t iptfs_api_test_main;

static int
api_iptfs_clear_counters (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_iptfs_clear_counters_t *mp;
  u32 sa_index = ~0u;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    if (!unformat (i, "sa_index %d", &sa_index))
      {
	clib_warning ("unknown input '%U'", format_unformat_error, i);
	return -99;
      }

  M (IPTFS_CLEAR_COUNTERS, mp);

  mp->sa_index = clib_host_to_net_u32 (sa_index);

  S (mp);
  W (ret);

  return ret;
}

#include <iptfs/iptfs.api_test.c>
