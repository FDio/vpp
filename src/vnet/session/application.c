/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_namespace.h>
#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

static app_main_t app_main;

#define app_interface_check_thread_and_barrier(_fn, _arg)		\
  if (PREDICT_FALSE (!vlib_thread_is_main_w_barrier ()))		\
    {									\
      vlib_rpc_call_main_thread (_fn, (u8 *) _arg, sizeof(*_arg));	\
      return 0;								\
    }

static app_listener_t *
app_listener_alloc (application_t * app)
{
  app_listener_t *app_listener;
  pool_get (app->listeners, app_listener);
  clib_memset (app_listener, 0, sizeof (*app_listener));
  app_listener->al_index = app_listener - app->listeners;
  app_listener->app_index = app->app_index;
  app_listener->session_index = SESSION_INVALID_INDEX;
  app_listener->local_index = SESSION_INVALID_INDEX;
  app_listener->ls_handle = SESSION_INVALID_HANDLE;
  return app_listener;
}

app_listener_t *
app_listener_get (application_t * app, u32 app_listener_index)
{
  return pool_elt_at_index (app->listeners, app_listener_index);
}

static void
app_listener_free (application_t * app, app_listener_t * app_listener)
{
  clib_bitmap_free (app_listener->workers);
  if (CLIB_DEBUG)
    clib_memset (app_listener, 0xfa, sizeof (*app_listener));
  pool_put (app->listeners, app_listener);
}

session_handle_t
app_listener_handle (app_listener_t * al)
{
  return al->ls_handle;
}

app_listener_t *
app_listener_get_w_session (session_t * ls)
{
  application_t *app;

  app = application_get_if_valid (ls->app_index);
  if (!app)
    return 0;
  return app_listener_get (app, ls->al_index);
}

session_handle_t
app_listen_session_handle (session_t * ls)
{
  app_listener_t *al;
  al = app_listener_get_w_session (ls);
  if (!al)
    return listen_session_get_handle (ls);
  return al->ls_handle;
}

app_listener_t *
app_listener_get_w_handle (session_handle_t handle)
{
  session_t *ls;
  ls = session_get_from_handle_if_valid (handle);
  if (!ls)
    return 0;
  return app_listener_get_w_session (ls);
}

app_listener_t *
app_listener_lookup (application_t * app, session_endpoint_cfg_t * sep_ext)
{
  u32 table_index, fib_proto;
  session_endpoint_t *sep;
  session_handle_t handle;
  session_t *ls;

  sep = (session_endpoint_t *) sep_ext;
  if (application_has_local_scope (app) && session_endpoint_is_local (sep))
    {
      table_index = application_local_session_table (app);
      handle = session_lookup_endpoint_listener (table_index, sep, 1);
      if (handle != SESSION_INVALID_HANDLE)
	{
	  ls = listen_session_get_from_handle (handle);
	  return app_listener_get_w_session (ls);
	}
    }

  fib_proto = session_endpoint_fib_proto (sep);
  table_index = session_lookup_get_index_for_fib (fib_proto, sep->fib_index);
  handle = session_lookup_endpoint_listener (table_index, sep, 1);
  if (handle != SESSION_INVALID_HANDLE)
    {
      ls = listen_session_get_from_handle (handle);
      return app_listener_get_w_session ((session_t *) ls);
    }

  return 0;
}

int
app_listener_alloc_and_init (application_t * app,
			     session_endpoint_cfg_t * sep,
			     app_listener_t ** listener)
{
  app_listener_t *app_listener;
  transport_connection_t *tc;
  u32 al_index, table_index;
  session_handle_t lh;
  session_type_t st;
  session_t *ls = 0;
  int rv;

  app_listener = app_listener_alloc (app);
  al_index = app_listener->al_index;
  st = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);

  /*
   * Add session endpoint to local session table. Only binds to "inaddr_any"
   * (i.e., zero address) are added to local scope table.
   */
  if (application_has_local_scope (app)
      && session_endpoint_is_local ((session_endpoint_t *) sep))
    {
      session_type_t local_st;

      local_st = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE,
						 sep->is_ip4);
      ls = listen_session_alloc (0, local_st);
      ls->app_index = app->app_index;
      ls->app_wrk_index = sep->app_wrk_index;
      lh = session_handle (ls);

      if ((rv = session_listen (ls, sep)))
	{
	  ls = session_get_from_handle (lh);
	  session_free (ls);
	  return rv;
	}

      ls = session_get_from_handle (lh);
      app_listener = app_listener_get (app, al_index);
      app_listener->local_index = ls->session_index;
      app_listener->ls_handle = lh;
      ls->al_index = al_index;

      table_index = application_local_session_table (app);
      session_lookup_add_session_endpoint (table_index,
					   (session_endpoint_t *) sep, lh);
    }

  if (application_has_global_scope (app))
    {
      /*
       * Start listening on local endpoint for requested transport and scope.
       * Creates a stream session with state LISTENING to be used in session
       * lookups, prior to establishing connection. Requests transport to
       * build it's own specific listening connection.
       */
      ls = listen_session_alloc (0, st);
      ls->app_index = app->app_index;
      ls->app_wrk_index = sep->app_wrk_index;

      /* Listen pool can be reallocated if the transport is
       * recursive (tls) */
      lh = listen_session_get_handle (ls);

      if ((rv = session_listen (ls, sep)))
	{
	  ls = listen_session_get_from_handle (lh);
	  session_free (ls);
	  return rv;
	}
      ls = listen_session_get_from_handle (lh);
      app_listener = app_listener_get (app, al_index);
      app_listener->session_index = ls->session_index;
      app_listener->ls_handle = lh;
      ls->al_index = al_index;

      /* Add to the global lookup table after transport was initialized.
       * Lookup table needs to be populated only now because sessions
       * with cut-through transport are are added to app local tables that
       * are not related to network fibs, i.e., cannot be added as
       * connections */
      tc = session_get_transport (ls);
      if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	{
	  fib_protocol_t fib_proto;
	  fib_proto = session_endpoint_fib_proto ((session_endpoint_t *) sep);
	  table_index = session_lookup_get_index_for_fib (fib_proto,
							  sep->fib_index);
	  ASSERT (table_index != SESSION_TABLE_INVALID_INDEX);
	  session_lookup_add_session_endpoint (table_index,
					       (session_endpoint_t *) sep,
					       lh);
	}
    }

  if (!ls)
    {
      app_listener_free (app, app_listener);
      return -1;
    }

  *listener = app_listener;
  return 0;
}

void
app_listener_cleanup (app_listener_t * al)
{
  application_t *app = application_get (al->app_index);
  session_t *ls;

  if (al->session_index != SESSION_INVALID_INDEX)
    {
      ls = session_get (al->session_index, 0);
      session_stop_listen (ls);
      listen_session_free (ls);
    }
  if (al->local_index != SESSION_INVALID_INDEX)
    {
      session_endpoint_t sep = SESSION_ENDPOINT_NULL;
      u32 table_index;

      table_index = application_local_session_table (app);
      ls = listen_session_get (al->local_index);
      ct_session_endpoint (ls, &sep);
      session_lookup_del_session_endpoint (table_index, &sep);
      session_stop_listen (ls);
      listen_session_free (ls);
    }
  app_listener_free (app, al);
}

static app_worker_t *
app_listener_select_worker (application_t * app, app_listener_t * al)
{
  u32 wrk_index;

  app = application_get (al->app_index);
  wrk_index = clib_bitmap_next_set (al->workers, al->accept_rotor + 1);
  if (wrk_index == ~0)
    wrk_index = clib_bitmap_first_set (al->workers);

  ASSERT (wrk_index != ~0);
  al->accept_rotor = wrk_index;
  return application_get_worker (app, wrk_index);
}

session_t *
app_listener_get_session (app_listener_t * al)
{
  if (al->session_index == SESSION_INVALID_INDEX)
    return 0;

  return listen_session_get (al->session_index);
}

session_t *
app_listener_get_local_session (app_listener_t * al)
{
  if (al->local_index == SESSION_INVALID_INDEX)
    return 0;
  return listen_session_get (al->local_index);
}

static app_worker_map_t *
app_worker_map_alloc (application_t * app)
{
  app_worker_map_t *map;
  pool_get (app->worker_maps, map);
  clib_memset (map, 0, sizeof (*map));
  return map;
}

static u32
app_worker_map_index (application_t * app, app_worker_map_t * map)
{
  return (map - app->worker_maps);
}

static void
app_worker_map_free (application_t * app, app_worker_map_t * map)
{
  pool_put (app->worker_maps, map);
}

static app_worker_map_t *
app_worker_map_get (application_t * app, u32 map_index)
{
  if (pool_is_free_index (app->worker_maps, map_index))
    return 0;
  return pool_elt_at_index (app->worker_maps, map_index);
}

static const u8 *
app_get_name (application_t * app)
{
  return app->name;
}

u32
application_session_table (application_t * app, u8 fib_proto)
{
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app->ns_index);
  if (!application_has_global_scope (app))
    return APP_INVALID_INDEX;
  if (fib_proto == FIB_PROTOCOL_IP4)
    return session_lookup_get_index_for_fib (fib_proto,
					     app_ns->ip4_fib_index);
  else
    return session_lookup_get_index_for_fib (fib_proto,
					     app_ns->ip6_fib_index);
}

u32
application_local_session_table (application_t * app)
{
  app_namespace_t *app_ns;
  if (!application_has_local_scope (app))
    return APP_INVALID_INDEX;
  app_ns = app_namespace_get (app->ns_index);
  return app_ns->local_table_index;
}

/**
 * Returns app name for app-index
 */
const u8 *
application_name_from_index (u32 app_index)
{
  application_t *app = application_get (app_index);
  if (!app)
    return 0;
  return app_get_name (app);
}

static void
application_api_table_add (u32 app_index, u32 api_client_index)
{
  if (api_client_index != APP_INVALID_INDEX)
    hash_set (app_main.app_by_api_client_index, api_client_index, app_index);
}

static void
application_api_table_del (u32 api_client_index)
{
  hash_unset (app_main.app_by_api_client_index, api_client_index);
}

static void
application_name_table_add (application_t * app)
{
  hash_set_mem (app_main.app_by_name, app->name, app->app_index);
}

static void
application_name_table_del (application_t * app)
{
  hash_unset_mem (app_main.app_by_name, app->name);
}

application_t *
application_lookup (u32 api_client_index)
{
  uword *p;
  p = hash_get (app_main.app_by_api_client_index, api_client_index);
  if (p)
    return application_get_if_valid (p[0]);

  return 0;
}

application_t *
application_lookup_name (const u8 * name)
{
  uword *p;
  p = hash_get_mem (app_main.app_by_name, name);
  if (p)
    return application_get (p[0]);

  return 0;
}

void
app_pending_rx_mqs_add_tail (app_wrk_t *aw, app_rx_mq_elt_t *elt)
{
  app_rx_mq_elt_t *head;

  if (!aw->pending_rx_mqs)
    {
      elt->next = elt->prev = elt;
      aw->pending_rx_mqs = elt;
      return;
    }

  head = aw->pending_rx_mqs;

  ASSERT (head != elt);

  elt->prev = head->prev;
  elt->next = head;

  head->prev->next = elt;
  head->prev = elt;
}

void
app_pending_rx_mqs_del (app_wrk_t *aw, app_rx_mq_elt_t *elt)
{
  if (elt->next == elt)
    {
      elt->next = elt->prev = 0;
      aw->pending_rx_mqs = 0;
      return;
    }

  if (elt == aw->pending_rx_mqs)
    aw->pending_rx_mqs = elt->next;

  elt->next->prev = elt->prev;
  elt->prev->next = elt->next;
  elt->next = elt->prev = 0;
}

vlib_node_registration_t app_rx_mqs_input_node;

VLIB_NODE_FN (app_rx_mqs_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 thread_index = vm->thread_index, n_msgs = 0;
  app_rx_mq_elt_t *elt, *next;
  app_main_t *am = &app_main;
  session_worker_t *wrk;
  app_wrk_t *aw;
  u64 buf;

  aw = &am->wrk[thread_index];
  elt = aw->pending_rx_mqs;
  if (!elt)
    return 0;

  wrk = session_main_get_worker (thread_index);

  do
    {
      if (!(elt->flags & APP_RX_MQ_F_POSTPONED))
	(void) read (svm_msg_q_get_eventfd (elt->mq), &buf, sizeof (buf));
      n_msgs += session_wrk_handle_mq (wrk, elt->mq);

      next = elt->next;
      app_pending_rx_mqs_del (aw, elt);
      if (!svm_msg_q_is_empty (elt->mq))
	{
	  elt->flags |= APP_RX_MQ_F_POSTPONED;
	  app_pending_rx_mqs_add_tail (aw, elt);
	}
      else
	{
	  elt->flags = 0;
	}
      elt = next;
    }
  while (aw->pending_rx_mqs && elt != aw->pending_rx_mqs);

  if (aw->pending_rx_mqs)
    vlib_node_set_interrupt_pending (vm, app_rx_mqs_input_node.index);

  return n_msgs;
}

VLIB_REGISTER_NODE (app_rx_mqs_input_node) = {
  .name = "app-rx-mqs-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
app_rx_mq_fd_read_ready (clib_file_t *cf)
{
  app_rx_mq_handle_t *handle = (app_rx_mq_handle_t *) &cf->private_data;
  vlib_main_t *vm = vlib_get_main ();
  app_main_t *am = &app_main;
  app_rx_mq_elt_t *mqe;
  application_t *app;
  app_wrk_t *aw;

  ASSERT (vlib_get_thread_index () == handle->thread_index);
  app = application_get_if_valid (handle->app_index);
  if (!app)
    return 0;

  mqe = &app->rx_mqs[handle->thread_index];
  if ((mqe->flags & APP_RX_MQ_F_PENDING) || svm_msg_q_is_empty (mqe->mq))
    return 0;

  aw = &am->wrk[handle->thread_index];
  app_pending_rx_mqs_add_tail (aw, mqe);
  mqe->flags |= APP_RX_MQ_F_PENDING;

  vlib_node_set_interrupt_pending (vm, app_rx_mqs_input_node.index);

  return 0;
}

static clib_error_t *
app_rx_mq_fd_write_ready (clib_file_t *cf)
{
  clib_warning ("should not be called");
  return 0;
}

static void
app_rx_mqs_epoll_add (application_t *app, app_rx_mq_elt_t *mqe)
{
  clib_file_t template = { 0 };
  app_rx_mq_handle_t handle;
  u32 thread_index;
  int fd;

  thread_index = mqe - app->rx_mqs;
  fd = svm_msg_q_get_eventfd (mqe->mq);

  handle.app_index = app->app_index;
  handle.thread_index = thread_index;

  template.read_function = app_rx_mq_fd_read_ready;
  template.write_function = app_rx_mq_fd_write_ready;
  template.file_descriptor = fd;
  template.private_data = handle.as_u64;
  template.polling_thread_index = thread_index;
  template.description =
    format (0, "app-%u-rx-mq-%u", app->app_index, thread_index);
  mqe->file_index = clib_file_add (&file_main, &template);
}

static void
app_rx_mqs_epoll_del (application_t *app, app_rx_mq_elt_t *mqe)
{
  u32 thread_index = mqe - app->rx_mqs;
  app_main_t *am = &app_main;
  app_wrk_t *aw;

  aw = &am->wrk[thread_index];

  if (mqe->flags & APP_RX_MQ_F_PENDING)
    {
      session_wrk_handle_mq (session_main_get_worker (thread_index), mqe->mq);
      app_pending_rx_mqs_del (aw, mqe);
    }

  clib_file_del_by_index (&file_main, mqe->file_index);
}

svm_msg_q_t *
application_rx_mq_get (application_t *app, u32 mq_index)
{
  if (!app->rx_mqs)
    return 0;

  return app->rx_mqs[mq_index].mq;
}

static void
app_rx_mqs_alloc (application_t *app)
{
  u32 evt_q_length, evt_size = sizeof (session_event_t);
  fifo_segment_t *eqs = &app->rx_mqs_segment;
  segment_manager_props_t *props;
  u32 n_mqs = vlib_num_workers () + 1;
  int i;

  props = application_segment_manager_properties (app);
  evt_q_length = clib_max (props->evt_q_size, 128);

  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
    { evt_q_length, evt_size, 0 }, { evt_q_length >> 1, 256, 0 }
  };
  cfg->consumer_pid = 0;
  cfg->n_rings = 2;
  cfg->q_nitems = evt_q_length;
  cfg->ring_cfgs = rc;

  eqs->ssvm.ssvm_size = svm_msg_q_size_to_alloc (cfg) * n_mqs + (16 << 10);
  eqs->ssvm.name = format (0, "%s-rx-mqs-seg%c", app->name, 0);

  if (ssvm_server_init (&eqs->ssvm, SSVM_SEGMENT_MEMFD))
    {
      clib_warning ("failed to initialize queue segment");
      return;
    }

  fifo_segment_init (eqs);

  /* Fifo segment filled only with mqs */
  eqs->h->n_mqs = n_mqs;
  vec_validate (app->rx_mqs, n_mqs - 1);

  for (i = 0; i < n_mqs; i++)
    {
      app->rx_mqs[i].mq = fifo_segment_msg_q_alloc (eqs, i, cfg);
      if (svm_msg_q_alloc_eventfd (app->rx_mqs[i].mq))
	clib_warning ("eventfd returned");
      app_rx_mqs_epoll_add (app, &app->rx_mqs[i]);
      app->rx_mqs[i].app_index = app->app_index;
    }
}

u8
application_use_private_rx_mqs (void)
{
  return session_main.use_private_rx_mqs;
}

fifo_segment_t *
application_get_rx_mqs_segment (application_t *app)
{
  if (application_use_private_rx_mqs ())
    return &app->rx_mqs_segment;
  return session_main_get_evt_q_segment ();
}

void
application_enable_rx_mqs_nodes (u8 is_en)
{
  u8 state = is_en ? VLIB_NODE_STATE_INTERRUPT : VLIB_NODE_STATE_DISABLED;

  foreach_vlib_main (({
    vlib_node_set_state (this_vlib_main, app_rx_mqs_input_node.index, state);
  }));
}

static application_t *
application_alloc (void)
{
  application_t *app;
  pool_get (app_main.app_pool, app);
  clib_memset (app, 0, sizeof (*app));
  app->app_index = app - app_main.app_pool;
  return app;
}

application_t *
application_get (u32 app_index)
{
  if (app_index == APP_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (app_main.app_pool, app_index);
}

application_t *
application_get_if_valid (u32 app_index)
{
  if (pool_is_free_index (app_main.app_pool, app_index))
    return 0;

  return pool_elt_at_index (app_main.app_pool, app_index);
}

static void
application_verify_cb_fns (session_cb_vft_t * cb_fns)
{
  if (cb_fns->session_accept_callback == 0)
    clib_warning ("No accept callback function provided");
  if (cb_fns->session_connected_callback == 0)
    clib_warning ("No session connected callback function provided");
  if (cb_fns->session_disconnect_callback == 0)
    clib_warning ("No session disconnect callback function provided");
  if (cb_fns->session_reset_callback == 0)
    clib_warning ("No session reset callback function provided");
}

/**
 * Check app config for given segment type
 *
 * Returns 1 on success and 0 otherwise
 */
static u8
application_verify_cfg (ssvm_segment_type_t st)
{
  u8 is_valid;
  if (st == SSVM_SEGMENT_MEMFD)
    {
      is_valid = (session_main_get_evt_q_segment () != 0);
      if (!is_valid)
	clib_warning ("memfd seg: vpp's event qs IN binary api svm region");
      return is_valid;
    }
  else if (st == SSVM_SEGMENT_SHM)
    {
      is_valid = (session_main_get_evt_q_segment () == 0);
      if (!is_valid)
	clib_warning ("shm seg: vpp's event qs NOT IN binary api svm region");
      return is_valid;
    }
  else
    return 1;
}

static int
application_alloc_and_init (app_init_args_t * a)
{
  ssvm_segment_type_t seg_type = SSVM_SEGMENT_MEMFD;
  segment_manager_props_t *props;
  application_t *app;
  u64 *options;

  app = application_alloc ();
  options = a->options;
  /*
   * Make sure we support the requested configuration
   */
  if (options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_IS_BUILTIN)
    seg_type = SSVM_SEGMENT_PRIVATE;

  if ((options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
      && seg_type != SSVM_SEGMENT_MEMFD)
    {
      clib_warning ("mq eventfds can only be used if socket transport is "
		    "used for binary api");
      return VNET_API_ERROR_APP_UNSUPPORTED_CFG;
    }

  if (!application_verify_cfg (seg_type))
    return VNET_API_ERROR_APP_UNSUPPORTED_CFG;

  if (options[APP_OPTIONS_PREALLOC_FIFO_PAIRS]
      && options[APP_OPTIONS_PREALLOC_FIFO_HDRS])
    return VNET_API_ERROR_APP_UNSUPPORTED_CFG;

  /* Check that the obvious things are properly set up */
  application_verify_cb_fns (a->session_cb_vft);

  app->flags = options[APP_OPTIONS_FLAGS];
  app->cb_fns = *a->session_cb_vft;
  app->ns_index = options[APP_OPTIONS_NAMESPACE];
  app->proxied_transports = options[APP_OPTIONS_PROXY_TRANSPORT];
  app->name = vec_dup (a->name);

  /* If no scope enabled, default to global */
  if (!application_has_global_scope (app)
      && !application_has_local_scope (app))
    app->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  props = application_segment_manager_properties (app);
  segment_manager_props_init (props);
  props->segment_size = options[APP_OPTIONS_SEGMENT_SIZE];
  props->prealloc_fifos = options[APP_OPTIONS_PREALLOC_FIFO_PAIRS];
  props->prealloc_fifo_hdrs = options[APP_OPTIONS_PREALLOC_FIFO_HDRS];
  if (options[APP_OPTIONS_ADD_SEGMENT_SIZE])
    {
      props->add_segment_size = options[APP_OPTIONS_ADD_SEGMENT_SIZE];
      props->add_segment = 1;
    }
  if (options[APP_OPTIONS_RX_FIFO_SIZE])
    props->rx_fifo_size = options[APP_OPTIONS_RX_FIFO_SIZE];
  if (options[APP_OPTIONS_TX_FIFO_SIZE])
    props->tx_fifo_size = options[APP_OPTIONS_TX_FIFO_SIZE];
  if (options[APP_OPTIONS_EVT_QUEUE_SIZE])
    props->evt_q_size = options[APP_OPTIONS_EVT_QUEUE_SIZE];
  if (options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    props->use_mq_eventfd = 1;
  if (options[APP_OPTIONS_TLS_ENGINE])
    app->tls_engine = options[APP_OPTIONS_TLS_ENGINE];
  if (options[APP_OPTIONS_MAX_FIFO_SIZE])
    props->max_fifo_size = options[APP_OPTIONS_MAX_FIFO_SIZE];
  if (options[APP_OPTIONS_HIGH_WATERMARK])
    props->high_watermark = options[APP_OPTIONS_HIGH_WATERMARK];
  if (options[APP_OPTIONS_LOW_WATERMARK])
    props->low_watermark = options[APP_OPTIONS_LOW_WATERMARK];
  if (options[APP_OPTIONS_PCT_FIRST_ALLOC])
    props->pct_first_alloc = options[APP_OPTIONS_PCT_FIRST_ALLOC];
  props->segment_type = seg_type;

  /* Add app to lookup by api_client_index table */
  if (!application_is_builtin (app))
    application_api_table_add (app->app_index, a->api_client_index);
  else
    application_name_table_add (app);

  a->app_index = app->app_index;

  APP_DBG ("New app name: %v api index: %u index %u", app->name,
	   a->api_client_index, app->app_index);

  return 0;
}

static void
application_free (application_t * app)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  /*
   * The app event queue allocated in first segment is cleared with
   * the segment manager. No need to explicitly free it.
   */
  APP_DBG ("Delete app name %v index: %d", app->name, app->app_index);

  if (application_is_proxy (app))
    application_remove_proxy (app);

  /*
   * Free workers
   */

  /* *INDENT-OFF* */
  pool_flush (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_free (app_wrk);
  }));
  /* *INDENT-ON* */
  pool_free (app->worker_maps);

  /*
   * Free rx mqs if allocated
   */
  if (app->rx_mqs)
    {
      int i;
      for (i = 0; i < vec_len (app->rx_mqs); i++)
	app_rx_mqs_epoll_del (app, &app->rx_mqs[i]);

      fifo_segment_cleanup (&app->rx_mqs_segment);
      ssvm_delete (&app->rx_mqs_segment.ssvm);
      vec_free (app->rx_mqs);
    }

  /*
   * Cleanup remaining state
   */
  if (application_is_builtin (app))
    application_name_table_del (app);
  vec_free (app->name);
  pool_put (app_main.app_pool, app);
}

static void
application_detach_process (application_t * app, u32 api_client_index)
{
  vnet_app_worker_add_del_args_t _args = { 0 }, *args = &_args;
  app_worker_map_t *wrk_map;
  u32 *wrks = 0, *wrk_index;
  app_worker_t *app_wrk;

  if (api_client_index == ~0)
    {
      application_free (app);
      return;
    }

  APP_DBG ("Detaching for app %v index %u api client index %u", app->name,
	   app->app_index, api_client_index);

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps)  {
    app_wrk = app_worker_get (wrk_map->wrk_index);
    if (app_wrk->api_client_index == api_client_index)
      vec_add1 (wrks, app_wrk->wrk_index);
  }
  /* *INDENT-ON* */

  if (!vec_len (wrks))
    {
      clib_warning ("no workers for app %u api_index %u", app->app_index,
		    api_client_index);
      return;
    }

  args->app_index = app->app_index;
  args->api_client_index = api_client_index;
  vec_foreach (wrk_index, wrks)
  {
    app_wrk = app_worker_get (wrk_index[0]);
    args->wrk_map_index = app_wrk->wrk_map_index;
    args->is_add = 0;
    vnet_app_worker_add_del (args);
  }
  vec_free (wrks);
}

app_worker_t *
application_get_worker (application_t * app, u32 wrk_map_index)
{
  app_worker_map_t *map;
  map = app_worker_map_get (app, wrk_map_index);
  if (!map)
    return 0;
  return app_worker_get (map->wrk_index);
}

app_worker_t *
application_get_default_worker (application_t * app)
{
  return application_get_worker (app, 0);
}

u32
application_n_workers (application_t * app)
{
  return pool_elts (app->worker_maps);
}

app_worker_t *
application_listener_select_worker (session_t * ls)
{
  application_t *app;
  app_listener_t *al;

  app = application_get (ls->app_index);
  al = app_listener_get (app, ls->al_index);
  return app_listener_select_worker (app, al);
}

int
application_alloc_worker_and_init (application_t * app, app_worker_t ** wrk)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  int rv;

  app_wrk = app_worker_alloc (app);
  wrk_map = app_worker_map_alloc (app);
  wrk_map->wrk_index = app_wrk->wrk_index;
  app_wrk->wrk_map_index = app_worker_map_index (app, wrk_map);

  /*
   * Setup first segment manager
   */
  sm = segment_manager_alloc ();
  sm->app_wrk_index = app_wrk->wrk_index;

  if ((rv = segment_manager_init_first (sm)))
    {
      app_worker_free (app_wrk);
      return rv;
    }
  sm->first_is_protected = 1;

  /*
   * Setup app worker
   */
  app_wrk->first_segment_manager = segment_manager_index (sm);
  app_wrk->listeners_table = hash_create (0, sizeof (u64));
  app_wrk->event_queue = segment_manager_event_queue (sm);
  app_wrk->app_is_builtin = application_is_builtin (app);

  *wrk = app_wrk;

  return 0;
}

int
vnet_app_worker_add_del (vnet_app_worker_add_del_args_t * a)
{
  fifo_segment_t *fs;
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  application_t *app;
  int rv;

  app = application_get (a->app_index);
  if (!app)
    return VNET_API_ERROR_INVALID_VALUE;

  if (a->is_add)
    {
      if ((rv = application_alloc_worker_and_init (app, &app_wrk)))
	return rv;

      /* Map worker api index to the app */
      app_wrk->api_client_index = a->api_client_index;
      application_api_table_add (app->app_index, a->api_client_index);

      sm = segment_manager_get (app_wrk->first_segment_manager);
      fs = segment_manager_get_segment_w_lock (sm, 0);
      a->segment = &fs->ssvm;
      a->segment_handle = segment_manager_segment_handle (sm, fs);
      segment_manager_segment_reader_unlock (sm);
      a->evt_q = app_wrk->event_queue;
      a->wrk_map_index = app_wrk->wrk_map_index;
    }
  else
    {
      wrk_map = app_worker_map_get (app, a->wrk_map_index);
      if (!wrk_map)
	return VNET_API_ERROR_INVALID_VALUE;

      app_wrk = app_worker_get (wrk_map->wrk_index);
      if (!app_wrk)
	return VNET_API_ERROR_INVALID_VALUE;

      application_api_table_del (app_wrk->api_client_index);
      app_worker_free (app_wrk);
      app_worker_map_free (app, wrk_map);
      if (application_n_workers (app) == 0)
	application_free (app);
    }
  return 0;
}

static int
app_validate_namespace (u8 * namespace_id, u64 secret, u32 * app_ns_index)
{
  app_namespace_t *app_ns;
  if (vec_len (namespace_id) == 0)
    {
      /* Use default namespace */
      *app_ns_index = 0;
      return 0;
    }

  *app_ns_index = app_namespace_index_from_id (namespace_id);
  if (*app_ns_index == APP_NAMESPACE_INVALID_INDEX)
    return VNET_API_ERROR_APP_INVALID_NS;
  app_ns = app_namespace_get (*app_ns_index);
  if (!app_ns)
    return VNET_API_ERROR_APP_INVALID_NS;
  if (app_ns->ns_secret != secret)
    return VNET_API_ERROR_APP_WRONG_NS_SECRET;
  return 0;
}

static u8 *
app_name_from_api_index (u32 api_client_index)
{
  vl_api_registration_t *regp;
  regp = vl_api_client_index_to_registration (api_client_index);
  if (regp)
    return format (0, "%s", regp->name);

  clib_warning ("api client index %u does not have an api registration!",
		api_client_index);
  return format (0, "unknown");
}

/**
 * Attach application to vpp
 *
 * Allocates a vpp app, i.e., a structure that keeps back pointers
 * to external app and a segment manager for shared memory fifo based
 * communication with the external app.
 */
int
vnet_application_attach (vnet_app_attach_args_t * a)
{
  fifo_segment_t *fs;
  application_t *app = 0;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  u32 app_ns_index = 0;
  u8 *app_name = 0;
  u64 secret;
  int rv;

  if (a->api_client_index != APP_INVALID_INDEX)
    app = application_lookup (a->api_client_index);
  else if (a->name)
    app = application_lookup_name (a->name);
  else
    return VNET_API_ERROR_INVALID_VALUE;

  if (app)
    return VNET_API_ERROR_APP_ALREADY_ATTACHED;

  /* Socket api sets the name and validates namespace prior to attach */
  if (!a->use_sock_api)
    {
      if (a->api_client_index != APP_INVALID_INDEX)
	{
	  app_name = app_name_from_api_index (a->api_client_index);
	  a->name = app_name;
	}

      secret = a->options[APP_OPTIONS_NAMESPACE_SECRET];
      if ((rv = app_validate_namespace (a->namespace_id, secret,
					&app_ns_index)))
	return rv;
      a->options[APP_OPTIONS_NAMESPACE] = app_ns_index;
    }

  if ((rv = application_alloc_and_init ((app_init_args_t *) a)))
    return rv;

  app = application_get (a->app_index);
  if ((rv = application_alloc_worker_and_init (app, &app_wrk)))
    return rv;

  a->app_evt_q = app_wrk->event_queue;
  app_wrk->api_client_index = a->api_client_index;
  sm = segment_manager_get (app_wrk->first_segment_manager);
  fs = segment_manager_get_segment_w_lock (sm, 0);

  if (application_is_proxy (app))
    {
      application_setup_proxy (app);
      /* The segment manager pool is reallocated because a new listener
       * is added. Re-grab segment manager to avoid dangling reference */
      sm = segment_manager_get (app_wrk->first_segment_manager);
    }

  ASSERT (vec_len (fs->ssvm.name) <= 128);
  a->segment = &fs->ssvm;
  a->segment_handle = segment_manager_segment_handle (sm, fs);

  segment_manager_segment_reader_unlock (sm);

  if (!application_is_builtin (app) && application_use_private_rx_mqs ())
    app_rx_mqs_alloc (app);

  vec_free (app_name);
  return 0;
}

/**
 * Detach application from vpp
 */
int
vnet_application_detach (vnet_app_detach_args_t * a)
{
  application_t *app;

  app = application_get_if_valid (a->app_index);
  if (!app)
    {
      clib_warning ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  app_interface_check_thread_and_barrier (vnet_application_detach, a);
  application_detach_process (app, a->api_client_index);
  return 0;
}


static u8
session_endpoint_in_ns (session_endpoint_t * sep)
{
  u8 is_lep = session_endpoint_is_local (sep);
  if (!is_lep && sep->sw_if_index != ENDPOINT_INVALID_INDEX
      && !ip_interface_has_address (sep->sw_if_index, &sep->ip, sep->is_ip4))
    {
      clib_warning ("sw_if_index %u not configured with ip %U",
		    sep->sw_if_index, format_ip46_address, &sep->ip,
		    sep->is_ip4);
      return 0;
    }
  return (is_lep || ip_is_local (sep->fib_index, &sep->ip, sep->is_ip4));
}

static void
session_endpoint_update_for_app (session_endpoint_cfg_t * sep,
				 application_t * app, u8 is_connect)
{
  app_namespace_t *app_ns;
  u32 ns_index, fib_index;

  ns_index = app->ns_index;

  /* App is a transport proto, so fetch the calling app's ns */
  if (app->flags & APP_OPTIONS_FLAGS_IS_TRANSPORT_APP)
    ns_index = sep->ns_index;

  app_ns = app_namespace_get (ns_index);
  if (!app_ns)
    return;

  /* Ask transport and network to bind to/connect using local interface
   * that "supports" app's namespace. This will fix our local connection
   * endpoint.
   */

  /* If in default namespace and user requested a fib index use it */
  if (ns_index == 0 && sep->fib_index != ENDPOINT_INVALID_INDEX)
    fib_index = sep->fib_index;
  else
    fib_index = sep->is_ip4 ? app_ns->ip4_fib_index : app_ns->ip6_fib_index;
  sep->peer.fib_index = fib_index;
  sep->fib_index = fib_index;

  if (!is_connect)
    {
      sep->sw_if_index = app_ns->sw_if_index;
    }
  else
    {
      if (app_ns->sw_if_index != APP_NAMESPACE_INVALID_INDEX
	  && sep->peer.sw_if_index != ENDPOINT_INVALID_INDEX
	  && sep->peer.sw_if_index != app_ns->sw_if_index)
	clib_warning ("Local sw_if_index different from app ns sw_if_index");

      sep->peer.sw_if_index = app_ns->sw_if_index;
    }
}

int
vnet_listen (vnet_listen_args_t * a)
{
  app_listener_t *app_listener;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  ASSERT (vlib_thread_is_main_w_barrier ());

  app = application_get_if_valid (a->app_index);
  if (!app)
    return SESSION_E_NOAPP;

  app_wrk = application_get_worker (app, a->wrk_map_index);
  if (!app_wrk)
    return SESSION_E_INVALID_APPWRK;

  a->sep_ext.app_wrk_index = app_wrk->wrk_index;

  session_endpoint_update_for_app (&a->sep_ext, app, 0 /* is_connect */ );
  if (!session_endpoint_in_ns (&a->sep))
    return SESSION_E_INVALID_NS;

  /*
   * Check if we already have an app listener
   */
  app_listener = app_listener_lookup (app, &a->sep_ext);
  if (app_listener)
    {
      if (app_listener->app_index != app->app_index)
	return SESSION_E_ALREADY_LISTENING;
      if ((rv = app_worker_start_listen (app_wrk, app_listener)))
	return rv;
      a->handle = app_listener_handle (app_listener);
      return 0;
    }

  /*
   * Create new app listener
   */
  if ((rv = app_listener_alloc_and_init (app, &a->sep_ext, &app_listener)))
    return rv;

  if ((rv = app_worker_start_listen (app_wrk, app_listener)))
    {
      app_listener_cleanup (app_listener);
      return rv;
    }

  a->handle = app_listener_handle (app_listener);
  return 0;
}

int
vnet_connect (vnet_connect_args_t * a)
{
  app_worker_t *client_wrk;
  application_t *client;

  ASSERT (vlib_thread_is_main_w_barrier ());

  if (session_endpoint_is_zero (&a->sep))
    return SESSION_E_INVALID_RMT_IP;

  client = application_get (a->app_index);
  session_endpoint_update_for_app (&a->sep_ext, client, 1 /* is_connect */ );
  client_wrk = application_get_worker (client, a->wrk_map_index);

  /*
   * First check the local scope for locally attached destinations.
   * If we have local scope, we pass *all* connects through it since we may
   * have special policy rules even for non-local destinations, think proxy.
   */
  if (application_has_local_scope (client))
    {
      int rv;

      a->sep_ext.original_tp = a->sep_ext.transport_proto;
      a->sep_ext.transport_proto = TRANSPORT_PROTO_NONE;
      rv = app_worker_connect_session (client_wrk, &a->sep, a->api_context);
      if (rv <= 0)
	return rv;
      a->sep_ext.transport_proto = a->sep_ext.original_tp;
    }
  /*
   * Not connecting to a local server, propagate to transport
   */
  return app_worker_connect_session (client_wrk, &a->sep, a->api_context);
}

int
vnet_unlisten (vnet_unlisten_args_t * a)
{
  app_worker_t *app_wrk;
  app_listener_t *al;
  application_t *app;

  ASSERT (vlib_thread_is_main_w_barrier ());

  if (!(app = application_get_if_valid (a->app_index)))
    return SESSION_E_NOAPP;

  if (!(al = app_listener_get_w_handle (a->handle)))
    return SESSION_E_NOLISTEN;

  if (al->app_index != app->app_index)
    {
      clib_warning ("app doesn't own handle %llu!", a->handle);
      return SESSION_E_OWNER;
    }

  app_wrk = application_get_worker (app, a->wrk_map_index);
  if (!app_wrk)
    {
      clib_warning ("no app %u worker %u", app->app_index, a->wrk_map_index);
      return SESSION_E_INVALID_APPWRK;
    }

  return app_worker_stop_listen (app_wrk, al);
}

int
vnet_disconnect_session (vnet_disconnect_args_t * a)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get_from_handle_if_valid (a->handle);
  if (!s)
    return SESSION_E_NOSESSION;

  app_wrk = app_worker_get (s->app_wrk_index);
  if (app_wrk->app_index != a->app_index)
    return SESSION_E_OWNER;

  /* We're peeking into another's thread pool. Make sure */
  ASSERT (s->session_index == session_index_from_handle (a->handle));

  session_close (s);
  return 0;
}

int
application_change_listener_owner (session_t * s, app_worker_t * app_wrk)
{
  app_worker_t *old_wrk = app_worker_get (s->app_wrk_index);
  app_listener_t *app_listener;
  application_t *app;
  int rv;

  if (!old_wrk)
    return SESSION_E_INVALID_APPWRK;

  hash_unset (old_wrk->listeners_table, listen_session_get_handle (s));
  if (session_transport_service_type (s) == TRANSPORT_SERVICE_CL
      && s->rx_fifo)
    segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);

  app = application_get (old_wrk->app_index);
  if (!app)
    return SESSION_E_NOAPP;

  app_listener = app_listener_get (app, s->al_index);

  /* Only remove from lb for now */
  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   old_wrk->wrk_map_index, 0);

  if ((rv = app_worker_start_listen (app_wrk, app_listener)))
    return rv;

  s->app_wrk_index = app_wrk->wrk_index;

  return 0;
}

int
application_is_proxy (application_t * app)
{
  return (app->flags & APP_OPTIONS_FLAGS_IS_PROXY);
}

int
application_is_builtin (application_t * app)
{
  return (app->flags & APP_OPTIONS_FLAGS_IS_BUILTIN);
}

int
application_is_builtin_proxy (application_t * app)
{
  return (application_is_proxy (app) && application_is_builtin (app));
}

u8
application_has_local_scope (application_t * app)
{
  return app->flags & APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
}

u8
application_has_global_scope (application_t * app)
{
  return app->flags & APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
}

static clib_error_t *
application_start_stop_proxy_fib_proto (application_t * app, u8 fib_proto,
					u8 transport_proto, u8 is_start)
{
  app_namespace_t *app_ns = app_namespace_get (app->ns_index);
  u8 is_ip4 = (fib_proto == FIB_PROTOCOL_IP4);
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  app_listener_t *al;
  session_t *s;
  u32 flags;

  /* TODO decide if we want proxy to be enabled for all workers */
  app_wrk = application_get_default_worker (app);
  if (is_start)
    {
      s = app_worker_first_listener (app_wrk, fib_proto, transport_proto);
      if (!s)
	{
	  sep.is_ip4 = is_ip4;
	  sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
	  sep.sw_if_index = app_ns->sw_if_index;
	  sep.transport_proto = transport_proto;
	  sep.app_wrk_index = app_wrk->wrk_index;	/* only default */

	  /* force global scope listener */
	  flags = app->flags;
	  app->flags &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
	  app_listener_alloc_and_init (app, &sep, &al);
	  app->flags = flags;

	  app_worker_start_listen (app_wrk, al);
	  s = listen_session_get (al->session_index);
	  s->flags |= SESSION_F_PROXY;
	}
    }
  else
    {
      s = app_worker_proxy_listener (app_wrk, fib_proto, transport_proto);
      ASSERT (s);
    }

  tc = listen_session_get_transport (s);

  if (!ip_is_zero (&tc->lcl_ip, 1))
    {
      u32 sti;
      sep.is_ip4 = is_ip4;
      sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      sep.transport_proto = transport_proto;
      sep.port = 0;
      sti = session_lookup_get_index_for_fib (fib_proto, sep.fib_index);
      if (is_start)
	session_lookup_add_session_endpoint (sti,
					     (session_endpoint_t *) & sep,
					     s->session_index);
      else
	session_lookup_del_session_endpoint (sti,
					     (session_endpoint_t *) & sep);
    }

  return 0;
}

static void
application_start_stop_proxy_local_scope (application_t * app,
					  u8 transport_proto, u8 is_start)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app->ns_index);
  sep.is_ip4 = 1;
  sep.transport_proto = transport_proto;
  sep.port = 0;

  if (is_start)
    {
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->app_index);
      sep.is_ip4 = 0;
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->app_index);
    }
  else
    {
      session_lookup_del_session_endpoint (app_ns->local_table_index, &sep);
      sep.is_ip4 = 0;
      session_lookup_del_session_endpoint (app_ns->local_table_index, &sep);
    }
}

void
application_start_stop_proxy (application_t * app,
			      transport_proto_t transport_proto, u8 is_start)
{
  if (application_has_local_scope (app))
    application_start_stop_proxy_local_scope (app, transport_proto, is_start);

  if (application_has_global_scope (app))
    {
      application_start_stop_proxy_fib_proto (app, FIB_PROTOCOL_IP4,
					      transport_proto, is_start);
      application_start_stop_proxy_fib_proto (app, FIB_PROTOCOL_IP6,
					      transport_proto, is_start);
    }
}

void
application_setup_proxy (application_t * app)
{
  u16 transports = app->proxied_transports;
  transport_proto_t tp;

  ASSERT (application_is_proxy (app));

  /* *INDENT-OFF* */
  transport_proto_foreach (tp, ({
    if (transports & (1 << tp))
      application_start_stop_proxy (app, tp, 1);
  }));
  /* *INDENT-ON* */
}

void
application_remove_proxy (application_t * app)
{
  u16 transports = app->proxied_transports;
  transport_proto_t tp;

  ASSERT (application_is_proxy (app));

  /* *INDENT-OFF* */
  transport_proto_foreach (tp, ({
    if (transports & (1 << tp))
      application_start_stop_proxy (app, tp, 0);
  }));
  /* *INDENT-ON* */
}

segment_manager_props_t *
application_segment_manager_properties (application_t * app)
{
  return &app->sm_properties;
}

segment_manager_props_t *
application_get_segment_manager_properties (u32 app_index)
{
  application_t *app = application_get (app_index);
  return &app->sm_properties;
}

static void
application_format_listeners (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  u32 sm_index;
  u64 handle;

  if (!app)
    {
      vlib_cli_output (vm, "%U", format_app_worker_listener, 0 /* header */ ,
		       0, 0, verbose);
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps)  {
    app_wrk = app_worker_get (wrk_map->wrk_index);
    if (hash_elts (app_wrk->listeners_table) == 0)
      continue;
    hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
      vlib_cli_output (vm, "%U", format_app_worker_listener, app_wrk,
                       handle, sm_index, verbose);
    }));
  }
  /* *INDENT-ON* */
}

static void
application_format_connects (application_t * app, int verbose)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  if (!app)
    {
      app_worker_format_connects (0, verbose);
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps)  {
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_format_connects (app_wrk, verbose);
  }
  /* *INDENT-ON* */
}

u8 *
format_cert_key_pair (u8 * s, va_list * args)
{
  app_cert_key_pair_t *ckpair = va_arg (*args, app_cert_key_pair_t *);
  int key_len = 0, cert_len = 0;
  cert_len = vec_len (ckpair->cert);
  key_len = vec_len (ckpair->key);
  if (ckpair->cert_key_index == 0)
    s = format (s, "DEFAULT (cert:%d, key:%d)", cert_len, key_len);
  else
    s = format (s, "%d (cert:%d, key:%d)", ckpair->cert_key_index,
		cert_len, key_len);
  return s;
}

u8 *
format_crypto_engine (u8 * s, va_list * args)
{
  u32 engine = va_arg (*args, u32);
  switch (engine)
    {
    case CRYPTO_ENGINE_NONE:
      return format (s, "none");
    case CRYPTO_ENGINE_MBEDTLS:
      return format (s, "mbedtls");
    case CRYPTO_ENGINE_OPENSSL:
      return format (s, "openssl");
    case CRYPTO_ENGINE_PICOTLS:
      return format (s, "picotls");
    case CRYPTO_ENGINE_VPP:
      return format (s, "vpp");
    default:
      return format (s, "unknown engine");
    }
  return s;
}

uword
unformat_crypto_engine (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "mbedtls"))
    *a = CRYPTO_ENGINE_MBEDTLS;
  else if (unformat (input, "openssl"))
    *a = CRYPTO_ENGINE_OPENSSL;
  else if (unformat (input, "picotls"))
    *a = CRYPTO_ENGINE_PICOTLS;
  else if (unformat (input, "vpp"))
    *a = CRYPTO_ENGINE_VPP;
  else
    return 0;
  return 1;
}

u8 *
format_crypto_context (u8 * s, va_list * args)
{
  crypto_context_t *crctx = va_arg (*args, crypto_context_t *);
  s = format (s, "[0x%x][sub%d,ckpair%x]", crctx->ctx_index,
	      crctx->n_subscribers, crctx->ckpair_index);
  s = format (s, "[%U]", format_crypto_engine, crctx->crypto_engine);
  return s;
}

u8 *
format_application (u8 * s, va_list * args)
{
  application_t *app = va_arg (*args, application_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  segment_manager_props_t *props;
  const u8 *app_ns_name, *app_name;
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  if (app == 0)
    {
      if (!verbose)
	s = format (s, "%-10s%-20s%-40s", "Index", "Name", "Namespace");
      return s;
    }

  app_name = app_get_name (app);
  app_ns_name = app_namespace_id_from_index (app->ns_index);
  props = application_segment_manager_properties (app);
  if (!verbose)
    {
      s = format (s, "%-10u%-20v%-40v", app->app_index, app_name,
		  app_ns_name);
      return s;
    }

  s = format (s, "app-name %v app-index %u ns-index %u seg-size %U\n",
	      app_name, app->app_index, app->ns_index,
	      format_memory_size, props->add_segment_size);
  s = format (s, "rx-fifo-size %U tx-fifo-size %U workers:\n",
	      format_memory_size, props->rx_fifo_size,
	      format_memory_size, props->tx_fifo_size);

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps)  {
      app_wrk = app_worker_get (wrk_map->wrk_index);
      s = format (s, "%U", format_app_worker, app_wrk);
  }
  /* *INDENT-ON* */

  return s;
}

void
application_format_all_listeners (vlib_main_t * vm, int verbose)
{
  application_t *app;

  if (!pool_elts (app_main.app_pool))
    {
      vlib_cli_output (vm, "No active server bindings");
      return;
    }

  application_format_listeners (0, verbose);

  /* *INDENT-OFF* */
  pool_foreach (app, app_main.app_pool)  {
    application_format_listeners (app, verbose);
  }
  /* *INDENT-ON* */
}

void
application_format_all_clients (vlib_main_t * vm, int verbose)
{
  application_t *app;

  if (!pool_elts (app_main.app_pool))
    {
      vlib_cli_output (vm, "No active apps");
      return;
    }

  application_format_connects (0, verbose);

  /* *INDENT-OFF* */
  pool_foreach (app, app_main.app_pool)  {
    application_format_connects (app, verbose);
  }
  /* *INDENT-ON* */
}

static clib_error_t *
show_certificate_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  app_cert_key_pair_t *ckpair;
  session_cli_return_if_not_enabled ();

  /* *INDENT-OFF* */
  pool_foreach (ckpair, app_main.cert_key_pair_store)  {
    vlib_cli_output (vm, "%U", format_cert_key_pair, ckpair);
  }
  /* *INDENT-ON* */
  return 0;
}

static inline void
appliction_format_app_mq (vlib_main_t * vm, application_t * app)
{
  app_worker_map_t *map;
  app_worker_t *wrk;
  int i;

  /* *INDENT-OFF* */
  pool_foreach (map, app->worker_maps)  {
    wrk = app_worker_get (map->wrk_index);
    vlib_cli_output (vm, "[A%d][%d]%U", app->app_index,
		     map->wrk_index, format_svm_msg_q,
		     wrk->event_queue);
  }
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (app->rx_mqs); i++)
    vlib_cli_output (vm, "[A%d][R%d]%U", app->app_index, i, format_svm_msg_q,
		     app->rx_mqs[i].mq);
}

static clib_error_t *
appliction_format_all_app_mq (vlib_main_t * vm)
{
  application_t *app;
  int i, n_threads;

  n_threads = vec_len (vlib_mains);

  for (i = 0; i < n_threads; i++)
    {
      vlib_cli_output (vm, "[Ctrl%d]%U", i, format_svm_msg_q,
		       session_main_get_vpp_event_queue (i));
    }

  /* *INDENT-OFF* */
  pool_foreach (app, app_main.app_pool)  {
      appliction_format_app_mq (vm, app);
  }
  /* *INDENT-ON* */
  return 0;
}

static clib_error_t *
show_app_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  int do_server = 0, do_client = 0, do_mq = 0;
  application_t *app;
  u32 app_index = ~0;
  int verbose = 0;

  session_cli_return_if_not_enabled ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server"))
	do_server = 1;
      else if (unformat (input, "client"))
	do_client = 1;
      else if (unformat (input, "mq"))
	do_mq = 1;
      else if (unformat (input, "%u", &app_index))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (do_mq && app_index != ~0)
    {
      app = application_get_if_valid (app_index);
      if (!app)
	return clib_error_return (0, "No app with index %u", app_index);

      appliction_format_app_mq (vm, app);
      return 0;
    }

  if (do_mq)
    {
      appliction_format_all_app_mq (vm);
      return 0;
    }

  if (do_server)
    {
      application_format_all_listeners (vm, verbose);
      return 0;
    }

  if (do_client)
    {
      application_format_all_clients (vm, verbose);
      return 0;
    }

  if (app_index != ~0)
    {
      app = application_get_if_valid (app_index);
      if (!app)
	return clib_error_return (0, "No app with index %u", app_index);

      vlib_cli_output (vm, "%U", format_application, app, /* verbose */ 1);
      return 0;
    }

  /* Print app related info */
  if (!do_server && !do_client)
    {
      vlib_cli_output (vm, "%U", format_application, 0, 0);
      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool)  {
	vlib_cli_output (vm, "%U", format_application, app, 0);
      }
      /* *INDENT-ON* */
    }

  return 0;
}

/* Certificate store */

static app_cert_key_pair_t *
app_cert_key_pair_alloc ()
{
  app_cert_key_pair_t *ckpair;
  pool_get (app_main.cert_key_pair_store, ckpair);
  clib_memset (ckpair, 0, sizeof (*ckpair));
  ckpair->cert_key_index = ckpair - app_main.cert_key_pair_store;
  return ckpair;
}

app_cert_key_pair_t *
app_cert_key_pair_get_if_valid (u32 index)
{
  if (pool_is_free_index (app_main.cert_key_pair_store, index))
    return 0;
  return app_cert_key_pair_get (index);
}

app_cert_key_pair_t *
app_cert_key_pair_get (u32 index)
{
  return pool_elt_at_index (app_main.cert_key_pair_store, index);
}

app_cert_key_pair_t *
app_cert_key_pair_get_default ()
{
  /* To maintain legacy bapi */
  return app_cert_key_pair_get (0);
}

int
vnet_app_add_cert_key_pair (vnet_app_add_cert_key_pair_args_t * a)
{
  app_cert_key_pair_t *ckpair = app_cert_key_pair_alloc ();
  vec_validate (ckpair->cert, a->cert_len - 1);
  clib_memcpy_fast (ckpair->cert, a->cert, a->cert_len);
  vec_validate (ckpair->key, a->key_len - 1);
  clib_memcpy_fast (ckpair->key, a->key, a->key_len);
  a->index = ckpair->cert_key_index;
  return 0;
}

int
vnet_app_add_cert_key_interest (u32 index, u32 app_index)
{
  app_cert_key_pair_t *ckpair;
  if (!(ckpair = app_cert_key_pair_get_if_valid (index)))
    return -1;
  if (vec_search (ckpair->app_interests, app_index) != ~0)
    vec_add1 (ckpair->app_interests, app_index);
  return 0;
}

int
vnet_app_del_cert_key_pair (u32 index)
{
  app_cert_key_pair_t *ckpair;
  application_t *app;
  u32 *app_index;

  if (!(ckpair = app_cert_key_pair_get_if_valid (index)))
    return (VNET_API_ERROR_INVALID_VALUE);

  vec_foreach (app_index, ckpair->app_interests)
  {
    if ((app = application_get_if_valid (*app_index))
	&& app->cb_fns.app_cert_key_pair_delete_callback)
      app->cb_fns.app_cert_key_pair_delete_callback (ckpair);
  }

  vec_free (ckpair->cert);
  vec_free (ckpair->key);
  pool_put (app_main.cert_key_pair_store, ckpair);
  return 0;
}

clib_error_t *
application_init (vlib_main_t * vm)
{
  app_main_t *am = &app_main;
  u32 n_workers;

  n_workers = vlib_num_workers ();

  /* Index 0 was originally used by legacy apis, maintain as invalid */
  (void) app_cert_key_pair_alloc ();
  am->last_crypto_engine = CRYPTO_ENGINE_LAST;
  am->app_by_name = hash_create_vec (0, sizeof (u8), sizeof (uword));

  vec_validate (am->wrk, n_workers);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (application_init);

VLIB_CLI_COMMAND (show_app_command, static) =
{
  .path = "show app",
  .short_help = "show app [app_id] [server|client] [mq] [verbose]",
  .function = show_app_command_fn,
};

VLIB_CLI_COMMAND (show_certificate_command, static) =
{
  .path = "show app certificate",
  .short_help = "list app certs and keys present in store",
  .function = show_certificate_command_fn,
};
/* *INDENT-ON* */

crypto_engine_type_t
app_crypto_engine_type_add (void)
{
  return (++app_main.last_crypto_engine);
}

u8
app_crypto_engine_n_types (void)
{
  return (app_main.last_crypto_engine + 1);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
