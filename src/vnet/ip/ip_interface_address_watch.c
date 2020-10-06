/*
 * ip_interface_watch.c; IP interface address watching
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C.
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip_interface.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip.api_types.h>

#include <vlibmemory/api.h>
#include <vnet/ip/ip_interface_address_watch.h>

/**
 * Database of registered watchers
 * The key for a watcher is {type, sw_if_index}
 * interface=~0 implies any.
 */
typedef struct ip_interface_address_watch_db_t_
{
  mhash_t ipiwdb_hash;
} ip_interface_address_watch_db_t;

typedef struct ip_interface_address_key_t_
{
  ip46_type_t ipia_type;
  u32 ipia_sw_if_index;
} ip_interface_address_key_t;

static ip_interface_address_watch_db_t ipiw_db;

static uword
ip_interface_address_event_process (vlib_main_t * vm,
				    vlib_node_runtime_t * rt,
				    vlib_frame_t * f)
{
  ip_interface_address_event_t *event, *events = NULL;
  uword event_type = ~0;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      events = vlib_process_get_event_data (vm, &event_type);

      switch (event_type)
	{
	case SW_INTERFACE_IP_ADDR_EVENT:
	  vec_foreach (event,
		       events) ip_interface_address_handle_event (event);
	  break;

	case ~0:		/* timeout? */
	  break;
	}

      vec_reset_length (events);
    }
  return 0;
}

VLIB_REGISTER_NODE (ip_interface_address_event_process_node,static) = {
  .function = ip_interface_address_event_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip-interface-address-event-process",
};



static clib_error_t *
want_ip_interface_address_events_reaper (u32 client_index)
{
  ip_interface_address_key_t *key, *empty_keys = NULL;
  ip_interface_address_watcher_t *watchers;
  uword *v;
  i32 pos;

  /* walk the entire IP interface watchers DB and remove the clients'
   * registrations.
   */

  mhash_foreach(key, v, &ipiw_db.ipiwdb_hash,
  ({
    watchers = (ip_interface_address_watcher_t*) *v;

    vec_foreach_index_backwards (pos, watchers) {
      if (watchers[pos].client_index == client_index)
        vec_del1(watchers, pos);
    }

    if (vec_len(watchers) == 0)
      vec_add1 (empty_keys, *key);
  }));

  vec_foreach (key, empty_keys)
    mhash_unset (&ipiw_db.ipiwdb_hash, key, NULL);
  vec_free (empty_keys);
  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_ip_interface_address_events_reaper);

static int
ip_interface_address_watch_cmp (const ip_interface_address_watcher_t * w1,
                                const ip_interface_address_watcher_t * w2)
{
  return (0 == clib_memcmp (w1, w2, sizeof(*w1)));
}

void
ip_interface_address_watch (ip46_type_t type,
                            u32 sw_if_index,
                            const ip_interface_address_watcher_t * watch)
{
  ip_interface_address_key_t key = {
    .ipia_sw_if_index = sw_if_index,
    .ipia_type = type,
  };
  ip_interface_address_watcher_t *ipws = NULL;
  uword *p;

  p = mhash_get (&ipiw_db.ipiwdb_hash, &key);

  if (p)
    {
      ipws = (ip_interface_address_watcher_t*) p[0];

      if (~0 != vec_search_with_function (ipws, watch,
                                          ip_interface_address_watch_cmp))
        /* duplicate */
        return;
    }

  vec_add1 (ipws, *watch);

  mhash_set (&ipiw_db.ipiwdb_hash, &key, (uword) ipws, NULL);
}

void
ip_interface_address_unwatch (ip46_type_t type,
                              u32 sw_if_index,
                              const ip_interface_address_watcher_t * watch)
{
  ip_interface_address_key_t key = {
    .ipia_sw_if_index = (sw_if_index == 0 ? ~0 : sw_if_index),
    .ipia_type = type,
  };
  ip_interface_address_watcher_t *ipws = NULL;
  uword *p;
  u32 pos;

  p = mhash_get (&ipiw_db.ipiwdb_hash, &key);

  if (!p)
    return;

  ipws = (ip_interface_address_watcher_t*) p[0];

  pos = vec_search_with_function (ipws, watch, ip_interface_address_watch_cmp);

  if (~0 == pos)
    return;

  vec_del1 (ipws, pos);

  if (vec_len(ipws) == 0) {
    mhash_unset (&ipiw_db.ipiwdb_hash, &key, NULL);
    vec_free (ipws);
  }
}

static void
common_interface_address_signal (ip46_type_t type,
                                 u32 sw_if_index,
                                 void * address,
                                 u32 prefix_len,
                                 u32 is_delete)
{
  ip_interface_address_watcher_t *watcher;
  ip_interface_address_watcher_t *watchers;
  ip_interface_address_key_t key;
  uword *p;
  int i;

  key.ipia_type = type;
  key.ipia_sw_if_index = sw_if_index;

  for (i = 0; i < 2; i++)
  {
    p = mhash_get (&ipiw_db.ipiwdb_hash, &key);

    /* second time around, search for the "wildcard" index */
    key.ipia_sw_if_index = ~0;

    if (p == NULL)
      continue;

    watchers = (ip_interface_address_watcher_t *)p[0];

    vec_foreach (watcher, watchers) {
      ip_interface_address_event_t *event;

      event = vlib_process_signal_event_data (vlib_get_main(),
                                              ip_interface_address_event_process_node.index,
                                              SW_INTERFACE_IP_ADDR_EVENT, 1,
                                              sizeof(*event));
      ip46_address_reset (&event->prefix.addr.ip);
      if (type == IP46_TYPE_IP4) {
        ip46_address_set_ip4 (&event->prefix.addr.ip, address);
        event->prefix.addr.version = AF_IP4;
      } else {
        ip46_address_set_ip6 (&event->prefix.addr.ip, address);
        event->prefix.addr.version = AF_IP6;
      }
      event->prefix.len = (u8)(prefix_len & 0xff);
      event->client_index = watcher->client_index;
      event->pid = watcher->pid;
      event->sw_if_index = sw_if_index;
      event->is_delete = is_delete;
    }
  }
}

/* ip_main_init() should register these functions */
static void
ip4_interface_address_signal (ip4_main_t * im,
                              uword opaque,
                              u32 sw_if_index,
                              ip4_address_t * address,
                              u32 prefix_len,
                              u32 if_address_index, u32 is_delete)
{
  common_interface_address_signal (IP46_TYPE_IP4, sw_if_index, address,
                                   prefix_len, is_delete);
}

static void
ip6_interface_address_signal (ip6_main_t * im,
                              uword opaque,
                              u32 sw_if_index,
                              ip6_address_t * address,
                              u32 prefix_len,
                              u32 if_address_index, u32 is_delete)
{
  common_interface_address_signal (IP46_TYPE_IP6, sw_if_index, address,
                                   prefix_len, is_delete);
}

void
ip46_interface_address_register_callbacks(void)
{
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;

  ip4_add_del_interface_address_callback_t cb4;
  ip6_add_del_interface_address_callback_t cb6;

  cb4.function = ip4_interface_address_signal;
  cb4.function_opaque = 0;
  vec_add1 (im4->add_del_interface_address_callbacks, cb4);

  cb6.function = ip6_interface_address_signal;
  cb6.function_opaque = 0;
  vec_add1 (im6->add_del_interface_address_callbacks, cb6);
}


static clib_error_t *
ip_interface_address_watchers_show (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  ip_interface_address_watcher_t *watchers, *watcher;
  ip_interface_address_key_t *key;
  uword *v;

  mhash_foreach(key, v, &ipiw_db.ipiwdb_hash,
  ({
    watchers = (ip_interface_address_watcher_t*) *v;

    ASSERT(vec_len(watchers));
    vlib_cli_output (vm, "Key: type %U interface index %u", format_ip46_type,
                     key->ipia_type, key->ipia_sw_if_index);

    vec_foreach (watcher, watchers)
      vlib_cli_output (vm, "  client index %u", watcher->client_index);
  }));
  return NULL;
}

VLIB_CLI_COMMAND (show_ip_interface_address_watchers_cmd_node, static) = {
  .path = "show ip interface-address-watcher",
  .function = ip_interface_address_watchers_show,
  .short_help = "show ip interface-address-watcher",
};

static clib_error_t *
ip_interface_address_watch_init (vlib_main_t * vm)
{
  mhash_init (&ipiw_db.ipiwdb_hash,
	      sizeof (ip_interface_address_watcher_t *),
	      sizeof (ip_interface_address_key_t));
  return NULL;
}

VLIB_INIT_FUNCTION (ip_interface_address_watch_init) =
{
  .runs_after = VLIB_INITS("ip4_init", "ip6_init"),
};
