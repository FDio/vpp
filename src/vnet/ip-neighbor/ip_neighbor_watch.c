/*
 * ip_neighboor_watch.c; IP neighbor watching
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 */

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_watch.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>

#include <vlibmemory/api.h>

/**
 * Database of registered watchers
 * The key for a watcher is {type, sw_if_index, addreess}
 * interface=~0 / address=all-zeros imples any.
 */
typedef struct ip_neighbor_watch_db_t_
{
  mhash_t ipnwdb_hash;
} ip_neighbor_watch_db_t;

static ip_neighbor_watch_db_t ipnw_db;

static uword
ip_neighbor_event_process (vlib_main_t * vm,
			   vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  ip_neighbor_event_t *ipne, *ipnes = NULL;
  uword event_type = ~0;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      ipnes = vlib_process_get_event_data (vm, &event_type);

      switch (event_type)
	{
	default:
	  vec_foreach (ipne, ipnes) ip_neighbor_handle_event (ipne);
	  break;

	case ~0:
	  /* timeout - */
	  break;
	}

      vec_reset_length (ipnes);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip_neighbor_event_process_node) = {
  .function = ip_neighbor_event_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip-neighbor-event",
};
/* *INDENT-ON* */


static clib_error_t *
want_ip_neighbor_events_reaper (u32 client_index)
{
  ip_neighbor_key_t *key, *empty_keys = NULL;
  ip_neighbor_watcher_t *watchers;
  uword *v;
  i32 pos;

  /* walk the entire IP neighbour DB and removes the client's registrations */
  /* *INDENT-OFF* */
  mhash_foreach(key, v, &ipnw_db.ipnwdb_hash,
  ({
    watchers = (ip_neighbor_watcher_t*) *v;

    vec_foreach_index_backwards (pos, watchers) {
      if (watchers[pos].ipw_client == client_index)
        vec_del1(watchers, pos);
    }

    if (vec_len(watchers) == 0)
      vec_add1 (empty_keys, *key);
  }));
  /* *INDENT-OFF* */

  vec_foreach (key, empty_keys)
    mhash_unset (&ipnw_db.ipnwdb_hash, key, NULL);
  vec_free (empty_keys);
  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_ip_neighbor_events_reaper);

static int
ip_neighbor_watch_cmp (const ip_neighbor_watcher_t * w1,
                       const ip_neighbor_watcher_t * w2)
{
  return (0 == clib_memcmp (w1, w2, sizeof(*w1)));
}

void
ip_neighbor_watch (const ip46_address_t * ip,
		   ip46_type_t type,
		   u32 sw_if_index,
                   const ip_neighbor_watcher_t * watch)
{
  ip_neighbor_key_t key = {
    .ipnk_ip = *ip,
    .ipnk_sw_if_index = (sw_if_index == 0 ? ~0 : sw_if_index),
    .ipnk_type = type,
  };
  ip_neighbor_watcher_t *ipws = NULL;
  uword *p;

  p = mhash_get (&ipnw_db.ipnwdb_hash, &key);

  if (p)
    {
      ipws = (ip_neighbor_watcher_t*) p[0];

      if (~0 != vec_search_with_function (ipws, watch,
                                          ip_neighbor_watch_cmp))
        /* duplicate */
        return;
    }

  vec_add1 (ipws, *watch);

  mhash_set (&ipnw_db.ipnwdb_hash, &key, (uword) ipws, NULL);
}

void
ip_neighbor_unwatch (const ip46_address_t * ip,
		     ip46_type_t type,
		     u32 sw_if_index,
                     const ip_neighbor_watcher_t * watch)
{
  ip_neighbor_key_t key = {
    .ipnk_ip = *ip,
    .ipnk_sw_if_index = (sw_if_index == 0 ? ~0 : sw_if_index),
    .ipnk_type = type,
  };
  ip_neighbor_watcher_t *ipws = NULL;
  uword *p;
  u32 pos;

  p = mhash_get (&ipnw_db.ipnwdb_hash, &key);

  if (!p)
    return;

  ipws = (ip_neighbor_watcher_t*) p[0];

  pos = vec_search_with_function (ipws, watch, ip_neighbor_watch_cmp);

  if (~0 == pos)
    return;

  vec_del1 (ipws, pos);

  if (vec_len(ipws) == 0)
    mhash_unset (&ipnw_db.ipnwdb_hash, &key, NULL);
}

static void
ip_neighbor_signal (ip_neighbor_watcher_t *watchers,
                    index_t ipni,
                    ip_neighbor_event_flags_t flags)
{
  ip_neighbor_watcher_t *watcher;

  vec_foreach (watcher, watchers) {
    ip_neighbor_event_t *ipne;

    ipne = vlib_process_signal_event_data (vlib_get_main(),
                                           ip_neighbor_event_process_node.index,
                                           0, 1, sizeof(*ipne));
    ipne->ipne_watch = *watcher;
    ipne->ipne_flags = flags;
    ip_neighbor_clone(ip_neighbor_get(ipni), &ipne->ipne_nbr);
  }
}

void
ip_neighbor_publish (index_t ipni,
                     ip_neighbor_event_flags_t flags)
{
  const ip_neighbor_t *ipn;
  ip_neighbor_key_t key;
  uword *p;

  ipn = ip_neighbor_get (ipni);

  clib_memcpy (&key, ipn->ipn_key, sizeof (key));

  /* Search the DB from longest to shortest key */
  p = mhash_get (&ipnw_db.ipnwdb_hash, &key);

  if (p) {
    ip_neighbor_signal ((ip_neighbor_watcher_t*) p[0], ipni, flags);
  }

  ip46_address_reset (&key.ipnk_ip);
  p = mhash_get (&ipnw_db.ipnwdb_hash, &key);

  if (p) {
    ip_neighbor_signal ((ip_neighbor_watcher_t*) p[0], ipni, flags);
  }

  key.ipnk_sw_if_index = ~0;
  p = mhash_get (&ipnw_db.ipnwdb_hash, &key);

  if (p) {
    ip_neighbor_signal ((ip_neighbor_watcher_t*) p[0], ipni, flags);
  }
}

static clib_error_t *
ip_neighbor_watchers_show (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  ip_neighbor_watcher_t *watchers, *watcher;
  ip_neighbor_key_t *key;
  uword *v;

  /* *INDENT-OFF* */
  mhash_foreach(key, v, &ipnw_db.ipnwdb_hash,
  ({
    watchers = (ip_neighbor_watcher_t*) *v;

    ASSERT(vec_len(watchers));
    vlib_cli_output (vm, "Key: %U", format_ip_neighbor_key, key);

    vec_foreach (watcher, watchers)
      vlib_cli_output (vm, "  %U", format_ip_neighbor_watcher, watcher);
  }));
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_neighbor_watchers_cmd_node, static) = {
  .path = "show ip neighbor-watcher",
  .function = ip_neighbor_watchers_show,
  .short_help = "show ip neighbors-watcher",
};
/* *INDENT-ON* */

static clib_error_t *
ip_neighbor_watch_init (vlib_main_t * vm)
{
  mhash_init (&ipnw_db.ipnwdb_hash,
	      sizeof (ip_neighbor_watcher_t *), sizeof (ip_neighbor_key_t));
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip_neighbor_watch_init) =
{
  .runs_after = VLIB_INITS("ip_neighbor_init"),
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
