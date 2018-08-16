/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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

#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dpi/dpi.h>

dpi_main_t dpi_main;
static dpi_entry_t *dpi_db = NULL;

#if CLIB_DEBUG > 0
#define dpi_debug clib_warning
#else
#define dpi_debug(...)              \
  do { } while (0)
#endif

void
dpi_cleanup_db_entry(dpi_entry_t *entry)
{
  hs_free_database(entry->database);
  hs_free_scratch(entry->scratch);
  vec_free(entry->expressions);
  vec_free(entry->flags);
  vec_free(entry->ids);

  memset(entry, 0, sizeof(dpi_entry_t));
}

int
dpi_get_db_contents(u32 db_index, regex_t ** expressions, u32 ** ids)
{
  dpi_entry_t *entry = NULL;

  entry = pool_elt_at_index (dpi_db, db_index);
  if (!entry)
    return -1;

  *expressions = entry->expressions;
  *ids = entry->ids;

  return 0;
}

int
dpi_add_multi_regex(dpi_args_t * args, u32 * db_index)
{
  dpi_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  dpi_args_t *arg = NULL;
  int error = 0;

  if (!args)
    return -1;

  if (vec_len(args) == 0)
    return -1;

  if (*db_index != ~0)
    {
      entry = pool_elt_at_index (dpi_db, *db_index);
      if (!entry)
        return -1;

      dpi_cleanup_db_entry(entry);
    }
  else
    {
      pool_get (dpi_db, entry);
      if (!entry)
        return -1;

      memset(entry, 0, sizeof(*entry));
      *db_index = entry - dpi_db;
    }

  vec_foreach (arg, args)
    {
      vec_add1(entry->ids, arg->index);
      vec_add1(entry->expressions, arg->rule);
      vec_add1(entry->flags, HS_FLAG_DOTALL);
    }

  if (hs_compile_multi((const char **)entry->expressions, entry->flags, entry->ids,
                       vec_len(entry->expressions),
                       HS_MODE_BLOCK, NULL, &entry->database,
                       &compile_err) != HS_SUCCESS)
    {
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch(entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database(entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

done:
  return error;
}



int
dpi_event_handler(unsigned int id, unsigned long long from,
                  unsigned long long to, unsigned int flags,
                  void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  dpi_cb_args_t *args = (dpi_cb_args_t*)ctx;

  args->id = id;
  args->res = 1;

  return 0;
}

int
dpi_db_lookup(u32 db_index, u8 * str, uint16_t length, u32 * app_index)
{
  dpi_entry_t *entry = NULL;
  int ret = 0;
  dpi_cb_args_t args = {};

  if (db_index == ~0)
    return -1;

  entry = pool_elt_at_index (dpi_db, db_index);
  if (!entry)
    return -1;

  ret = hs_scan(entry->database, (const char*)str, length, 0, entry->scratch,
                dpi_event_handler, (void*)&args);
  if (ret != HS_SUCCESS)
    return -1;

  if (args.res == 0)
    return -1;

  *app_index = args.id;

  return 0;
}

int
dpi_db_remove(u32 db_index)
{
  dpi_entry_t *entry = NULL;

  entry = pool_elt_at_index (dpi_db, db_index);
  if (!entry)
    return -1;

  dpi_cleanup_db_entry(entry);

  pool_put (dpi_db, entry);

  return 0;
}

void
dpi_add_rules(u32 app_index, dpi_app_t *app, dpi_args_t ** args, u8 path)
{
  u32 index = 0;
  u32 rule_index = 0;
  dpi_rule_t *rule = NULL;
  dpi_args_t arg;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);

     if (rule->path)
       {
         arg.index = app_index;
         if (path)
           {
             arg.rule = rule->path;
           }
         else
           {
             arg.rule = rule->host;
           }
         vec_add1(*args, arg);
       }
  }));
  /* *INDENT-ON* */
}

void
dpi_add_path_rules(u32 app_index, dpi_app_t *app, dpi_args_t ** args)
{
  return dpi_add_rules(app_index, app, args, 1);
}

void
dpi_add_host_rules(u32 app_index, dpi_app_t *app, dpi_args_t ** args)
{
  return dpi_add_rules(app_index, app, args, 0);
}

int
dpi_get_db_id(u8 *app_name, u32 *path_db_index, u32 *host_db_index)
{
  uword *p = NULL;
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app = NULL;

  p = hash_get_mem (dm->dpi_app_by_name, app_name);

  if (!p)
    return -1;

  app = pool_elt_at_index(dm->dpi_apps, p[0]);

  *path_db_index = app->path_db_index;
  *host_db_index = app->host_db_index;

  return 0;
}

int
dpi_create_update_db(u8 * app_name, u32 * path_db_index,
                     u32 * host_db_index)
{
  uword *p = NULL;
  dpi_args_t *args = NULL;
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app = NULL;
  int res = 0;

  p = hash_get_mem (dm->dpi_app_by_name, app_name);
  if (!p)
    return -1;
  app = pool_elt_at_index(dm->dpi_apps, p[0]);

  dpi_add_path_rules(p[0], app, &args);
  if (!args)
    return -1;
  res = dpi_add_multi_regex(args, path_db_index);
  vec_free(args);

  dpi_add_host_rules(p[0], app, &args);
  if (!args)
    return -1;
  res = dpi_add_multi_regex(args, host_db_index);
  vec_free(args);

  return res;
}


int
dpi_parse_ip4_packet(ip4_header_t * ip4, u32 path_db_id,
                     u32 host_db_id, u32 * app_index)
{
  int tcp_payload_len = 0;
  tcp_header_t *tcp = NULL;
  u8 *http = NULL;
  u8 *version = NULL;
  u8 *host = NULL;
  u8 *host_end = NULL;
  u16 uri_length = 0;
  u16 host_length = 0;
  int res = 0;
  u32 path_app_index = ~0;
  u32 host_app_index = ~0;

  if (path_db_id == ~0)
    return -1;

  if (host_db_id == ~0)
    return -1;

  if (ip4->protocol != IP_PROTOCOL_TCP)
    return -1;

  tcp = (tcp_header_t *) ip4_next_header(ip4);

  tcp_payload_len = clib_net_to_host_u16(ip4->length) -
                    sizeof(ip4_header_t) - tcp_header_bytes(tcp);

  if (tcp_payload_len < 8)
    return -1;

  http = (u8*)tcp + tcp_header_bytes(tcp);

  if ((http[0] != 'G') ||
      (http[1] != 'E') ||
      (http[2] != 'T'))
    {
      return -1;
    }

  /* scan HTTP URL */
  http += sizeof("GET");
  tcp_payload_len -= sizeof("GET");

  version = (u8*)strchr((const char*)http, ' ');
  if (version == NULL)
    return -1;

  uri_length = version - http;

  res = dpi_db_lookup(path_db_id, http,
                      MIN(uri_length, tcp_payload_len),
                      &path_app_index);

  if ((res < 0) || (path_app_index == ~0))
    return -1;

  /* scan HTTP Host */
  host = (u8*)strstr((const char*)http, "Host");
  if (host == NULL)
    return -1;

  host_end = (u8*)strchr((const char*)host, '\r');
  if (host_end == NULL)
    return -1;

  host_length = host_end - host;

  res = dpi_db_lookup(host_db_id, host,
                      MIN(host_length, tcp_payload_len),
                      &host_app_index);

  if ((res < 0) || (host_app_index == ~0))
    return -1;

  if (path_app_index != host_app_index)
    return -1;

  *app_index = host_app_index;

  return 0;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_dpi_bypass, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-dpi-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip6_dpi_bypass, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-dpi-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-on* */

void
vnet_int_dpi_bypass (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-dpi-bypass",
                 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-dpi-bypass",
                 sw_if_index, is_enable, 0, 0);
}

u32
dpi_parse_flagstr(char *flagsStr)
{
  u32 flags = 0;

  for (int i = 0; i < strlen(flagsStr); i++)
    {
      switch (flagsStr[i])
        {
          case 'i':
              flags |= HS_FLAG_CASELESS;
              break;
          case 'm':
              flags |= HS_FLAG_MULTILINE;
              break;
          case 's':
              flags |= HS_FLAG_DOTALL;
              break;
          case 'H':
              flags |= HS_FLAG_SINGLEMATCH;
              break;
          case 'V':
              flags |= HS_FLAG_ALLOWEMPTY;
              break;
          case '8':
              flags |= HS_FLAG_UTF8;
              break;
          case 'W':
              flags |= HS_FLAG_UCP;
              break;
          case '\r': /* stray carriage-return */
              break;
          default:
              break;
        }
    }
  return flags;
}


clib_error_t *
dpi_init (vlib_main_t * vm)
{
  dpi_main_t *dm = &dpi_main;

  dm->vnet_main = vnet_get_main ();
  dm->vlib_main = vm;

  return 0;
}

VLIB_INIT_FUNCTION (dpi_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deep Packet Inspection",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
