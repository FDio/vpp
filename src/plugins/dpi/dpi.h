/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#ifndef included_vnet_dpi_h
#define included_vnet_dpi_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>

#include <hs/hs.h>
#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

#define foreach_dpi_scan_next    \
_(DROP, "error-drop")                  \
_(INTERFACE, "interface-output" )      \
_(L2_INPUT, "l2-input")                \
_(IP4_INPUT,  "ip4-input")             \
_(IP6_INPUT, "ip6-input" )

typedef enum
{
#define _(s,n) DPI_SCAN_NEXT_##s,
  foreach_dpi_scan_next
#undef _
    DPI_SCAN_N_NEXT,
} dpi_scan_next_t;

#define foreach_dpi_error                       \
_(SCAN_FAIL, "failed to scan")

typedef enum
{
#define _(sym,str) DPI_ERROR_##sym,
  foreach_dpi_error
#undef _
    DPI_ERROR_N_ERROR,
} dpi_scan_error_t;

typedef enum
{
  DPI_ACTION_PERMIT,
  DPI_ACTION_DROP,
} dpi_action_t;

typedef u8 * regex_t;

typedef struct {
  /* App index */
  u32 index;
  /* Regex expression */
  regex_t rule;
} dpi_args_t;

typedef struct {
  regex_t *expressions;
  u32 *ids;
  u32 *flags;
  hs_database_t *database;
  hs_scratch_t *scratch;
} dpi_entry_t;

typedef struct {
  int res;
  u32 id;
} dpi_cb_args_t;

typedef struct {
  u32 id;
  regex_t host;
  regex_t path;
} dpi_rule_t;

typedef struct {
  regex_t host;
  regex_t path;
  u8 *src_ip;
  u8 *dst_ip;
} dpi_rule_args_t;

typedef struct {
  u32 id;
  u8 * name;
  /* Rules hash */
  uword* rules_by_id;
  /* Rules vector */
  dpi_rule_t *rules;
  /* DPI DB id */
  u32 path_db_index;
  u32 host_db_index;
} dpi_app_t;

typedef struct
{
  /* Compiler mode flags that affect the database as a whole.
   * HS_MODE_BLOCK or HS_MODE_STREAM or HS_MODE_VECTORED must be supplied */
  u32 mode;

  /*
   * Flags which modify the behaviour of the expression.
   * Multiple flags may be used by ORing them together.
   * Valid values are:
   *   HS_FLAG_CASELESS - Matching will be performed case-insensitively.
   *   HS_FLAG_DOTALL - Matching a . will not exclude newlines.
   *   HS_FLAG_MULTILINE - ^ and $ anchors match any newlines in data.
   *   HS_FLAG_SINGLEMATCH - Only one match will be generated for the expression per stream.
   *   HS_FLAG_ALLOWEMPTY - Allow expressions which can match against an empty string, such as .*.
   *   HS_FLAG_UTF8 - Treat this pattern as a sequence of UTF-8 characters.
   *   HS_FLAG_UCP - Use Unicode properties for character classes.
   *   HS_FLAG_PREFILTER - Compile pattern in prefiltering mode.
   *   HS_FLAG_SOM_LEFTMOST - Report the leftmost start of match offset when a match is found.
   */
  u32 flags;

  /* If not NULL, the platform structure is used to determine the target platform for the database.
   * If NULL, a database suitable for running on the current host platform is produced.
   */
  u32 platform;

  /* The NULL-terminated expression to parse */
  char *pattern;
  u32 pattern_len;
  /* Take action when matched */
  u32 action;

  /* Dpi compiled database (block mode) */
  hs_database_t *db_block;

  /* Dpi compiled database (streaming mode) */
  hs_database_t *db_streaming;

  /* Dpi temporary scratch space (used in both modes) */
  hs_scratch_t *scratch;

  /* Vector of Dpi stream state (used in streaming mode) */
  hs_stream_t *streams;

  /* DPI apps hash */
  uword* dpi_app_by_name;
  /* DPI apps vector */
  dpi_app_t *dpi_apps;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dpi_main_t;

extern dpi_main_t dpi_main;

#define MIN(x,y) (((x)<(y))?(x):(y))

void vnet_int_dpi_bypass (u32 sw_if_index, u8 is_ip6, u8 is_enable);
int dpi_get_db_id(u8 *app_name, u32 *path_db_index, u32 *host_db_index);
int dpi_get_db_contents(u32 db_index, regex_t ** expressions, u32 ** ids);
int dpi_db_lookup(u32 db_index, u8 * str, uint16_t length, u32 * app_index);
int dpi_db_remove(u32 db_index);
u32 dpi_parse_flagstr (char *flagsStr);
int dpi_create_update_db(u8 * app_name, u32 * path_db_index,
                         u32 * host_db_index);

int dpi_app_add_del(u8 * name, u8 add);

int dpi_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
                     dpi_rule_args_t * args);

#endif /* included_vnet_dpi_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
