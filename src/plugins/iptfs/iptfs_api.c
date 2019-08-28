/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * January 10 2020, Christian E. Hopps <chopps@labn.net>
 */
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <iptfs/ipsec_iptfs.h>

/* Declare message IDs */
#include <iptfs/iptfs.api_enum.h>
#include <iptfs/iptfs.api_types.h>

/* define message structures */
#define vl_typedefs
#include <iptfs/iptfs_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <iptfs/iptfs_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <iptfs/iptfs_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <iptfs/iptfs_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE ipsec_iptfs_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_iptfs_plugin_api_msg _ (IPTFS_CLEAR_COUNTERS, iptfs_clear_counters)

static void
vl_api_iptfs_clear_counters_t_handler (vl_api_iptfs_clear_counters_t *mp)
{
  vl_api_iptfs_clear_counters_reply_t *rmp;
  int rv = 0;
  iptfs_clear_counters ();
  REPLY_MACRO (VL_API_IPTFS_CLEAR_COUNTERS_REPLY);
}

#define vl_msg_name_crc_list
#include <iptfs/iptfs_all_api_h.h>
#undef vl_msg_name_crc_list

#include <iptfs/iptfs.api.c>

clib_error_t *
iptfs_api_hookup (vlib_main_t *vm)
{
  REPLY_MSG_ID_BASE = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (iptfs_api_hookup);
