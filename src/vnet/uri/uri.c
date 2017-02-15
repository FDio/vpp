/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/uri/uri.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

/** @file
    URI handling, bind tables
*/

/** Per-type vector of transport protocol virtual function tables*/
static transport_proto_vft_t *tp_vfts;

uri_main_t uri_main;
session_manager_main_t session_manager_main;

/** Allocate vpp event queue (once) per worker thread */
void
vpp_session_event_queue_allocate (session_manager_main_t *smm, u32 thread_index)
{
  api_main_t *am = &api_main;
  void *oldheap;

  if (smm->vpp_event_queues[thread_index] == 0)
    {
      /* Allocate event fifo in the /vpe-api shared-memory segment */
      oldheap = svm_push_data_heap (am->vlib_rp);

      smm->vpp_event_queues[thread_index] = unix_shared_memory_queue_init (
          2048 /* nels $$$$ config */, sizeof(fifo_event_t),
          0 /* consumer pid */,
          0 /* (do not) send signal when queue non-empty */);

      svm_pop_heap (oldheap);
    }
}

static void
make_v4_ss_kv (session_kv4_t *kv, ip4_address_t * lcl, ip4_address_t * rmt,
               u16 lcl_port, u16 rmt_port, u8 proto)
{
  v4_connection_key_t key;
  memset(&key, 0, sizeof(v4_connection_key_t));

  key.src.as_u32 = lcl->as_u32;
  key.dst.as_u32 = rmt->as_u32;
  key.src_port = lcl_port;
  key.dst_port = rmt_port;
  key.proto = proto;

  kv->key[0] = key.as_u64[0];
  kv->key[1] = key.as_u64[1];
  kv->value = ~0ULL;
}

static void
make_v4_listener_kv (session_kv4_t *kv, ip4_address_t * lcl, u16 lcl_port,
                     u8 proto)
{
  v4_connection_key_t key;
  memset(&key, 0, sizeof(v4_connection_key_t));

  key.src.as_u32 = lcl->as_u32;
  key.dst.as_u32 = 0;
  key.src_port = lcl_port;
  key.dst_port = 0;
  key.proto = proto;

  kv->key[0] = key.as_u64[0];
  kv->key[1] = key.as_u64[1];
  kv->value = ~0ULL;
}

static void
make_v4_ss_kv_from_tc (session_kv4_t * kv, transport_connection_t *t)
{
  return make_v4_ss_kv (kv, &t->lcl_ip.ip4, &t->rmt_ip.ip4, t->lcl_port,
                        t->rmt_port, t->proto);
}

static void
make_v6_ss_kv (session_kv6_t *kv, ip6_address_t * lcl, ip6_address_t * rmt,
               u16 lcl_port, u16 rmt_port, u8 proto)
{
  v6_connection_key_t key;
  memset(&key, 0, sizeof(v6_connection_key_t));

  key.src.as_u64[0] = lcl->as_u64[0];
  key.src.as_u64[1] = lcl->as_u64[1];
  key.dst.as_u64[0] = rmt->as_u64[0];
  key.dst.as_u64[1] = rmt->as_u64[1];
  key.src_port = lcl_port;
  key.dst_port = rmt_port;
  key.proto = proto;

  kv->key[0] = key.as_u64[0];
  kv->key[1] = key.as_u64[1];
  kv->value = ~0ULL;
}

static void
make_v6_listener_kv (session_kv6_t *kv, ip6_address_t * lcl, u16 lcl_port,
                     u8 proto)
{
  v6_connection_key_t key;
  memset(&key, 0, sizeof(v6_connection_key_t));

  key.src.as_u64[0] = lcl->as_u64[0];
  key.src.as_u64[1] = lcl->as_u64[1];
  key.dst.as_u64[0] = 0;
  key.dst.as_u64[1] = 0;
  key.src_port = lcl_port;
  key.dst_port = 0;
  key.proto = proto;

  kv->key[0] = key.as_u64[0];
  kv->key[1] = key.as_u64[1];
  kv->value = ~0ULL;
}

static void
make_v6_ss_kv_from_tc (session_kv6_t *kv, transport_connection_t *t)
{
  make_v6_ss_kv (kv, &t->lcl_ip.ip6, &t->rmt_ip.ip6, t->lcl_port,
                 t->rmt_port, t->proto);
}

static void
stream_session_table_add_for_tc (session_manager_main_t *smm, u8 sst,
                                 transport_connection_t * tc, u64 value)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&smm->v4_session_hash, &kv4, 1 /* is_add */);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&smm->v6_session_hash, &kv6, 1 /* is_add */);
      break;
    default:
      clib_warning("Session type not supported");
      ASSERT(0);
    }
}

void
stream_session_table_add (session_manager_main_t *smm, stream_session_t * s,
                          u64 value)
{
  transport_connection_t * tc;

  tc = tp_vfts[s->session_type].get_connection (s->connection_index,
                                                s->session_thread_index);
  stream_session_table_add_for_tc (smm, s->session_type, tc, value);
}

static void
stream_session_half_open_table_add (session_manager_main_t *smm, u8 sst,
                                    transport_connection_t * tc, u64 value)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&smm->v4_half_open_hash, &kv4, 1 /* is_add */);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&smm->v6_half_open_hash, &kv6, 1 /* is_add */);
      break;
    default:
      clib_warning("Session type not supported");
      ASSERT(0);
    }
}

static int
stream_session_table_del_for_tc (session_manager_main_t *smm, u8 sst,
                                 transport_connection_t * tc)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&smm->v4_session_hash, &kv4,
                                       0 /* is_add */);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&smm->v6_session_hash, &kv6,
                                       0 /* is_add */);
      break;
    default:
      clib_warning ("Session type not supported");
      ASSERT(0);
    }

  return 0;
}

static int
stream_session_table_del (session_manager_main_t *smm, stream_session_t *s)
{
  transport_connection_t * ts;

  ts = tp_vfts[s->session_type].get_connection (s->connection_index,
                                             s->session_thread_index);
  return stream_session_table_del_for_tc (smm, s->session_type, ts);
}

static void
stream_session_half_open_table_del (session_manager_main_t *smm, u8 sst,
                                    transport_connection_t *tc)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      clib_bihash_add_del_16_8 (&smm->v4_half_open_hash, &kv4, 0 /* is_add */);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      clib_bihash_add_del_48_8 (&smm->v6_half_open_hash, &kv6, 0 /* is_add */);
      break;
    default:
      clib_warning("Session type not supported");
      ASSERT(0);
    }
}

stream_session_t *
stream_session_lookup_listener4 (ip4_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  int rv;

  make_v4_listener_kv (&kv4, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], (u32) kv4.value);

  /* Zero out the lcl ip*/
  kv4.key[0] = 0;
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv4.value);

  return 0;
}

/** Looks up a session based on the 5-tuple passed as argument.
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces) */
stream_session_t *
stream_session_lookup4 (ip4_address_t * lcl, ip4_address_t * rmt, u16 lcl_port,
                        u16 rmt_port, u8 proto, u32 my_thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return stream_session_get_tsi (kv4.value, my_thread_index);

  /* If nothing is found, check if any listener is available */
  return stream_session_lookup_listener4 (lcl, lcl_port, proto);
}

stream_session_t *
stream_session_lookup_listener6 (ip6_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv6_t kv6;
  int rv;

  make_v6_listener_kv (&kv6, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv6.value);

  /* Zero out the lcl ip*/
  kv6.key[0] = kv6.key[1] = 0;
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv6.value);

  return 0;
}

/* Looks up a session based on the 5-tuple passed as argument.
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces) */
stream_session_t *
stream_session_lookup6 (ip6_address_t * lcl, ip6_address_t * rmt, u16 lcl_port,
                        u16 rmt_port, u8 proto, u32 my_thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return stream_session_get_tsi (kv6.value, my_thread_index);

  /* If nothing is found, check if any listener is available */
  return stream_session_lookup_listener6 (lcl, lcl_port, proto);
}

stream_session_t *
stream_session_lookup_listener (ip46_address_t * lcl, u16 lcl_port, u8 proto)
{
  switch (proto)
  {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      return stream_session_lookup_listener4 (&lcl->ip4, lcl_port, proto);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      return stream_session_lookup_listener6 (&lcl->ip6, lcl_port, proto);
      break;
  }
  return 0;
}

static u64
stream_session_half_open_lookup (session_manager_main_t *smm,
                                 ip46_address_t * lcl, ip46_address_t * rmt,
                                 u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  switch (proto)
  {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv (&kv4, &lcl->ip4, &rmt->ip4, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_16_8 (&smm->v4_half_open_hash, &kv4);

      if (rv == 0)
        return kv4.value;

      return (u64) ~0;
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv (&kv6, &lcl->ip6, &rmt->ip6, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_48_8 (&smm->v6_half_open_hash, &kv6);

      if (rv == 0)
        return kv6.value;

      return (u64) ~0;
      break;
  }
  return 0;
}

transport_connection_t *
stream_session_lookup_transport4 (session_manager_main_t *smm,
                                  ip4_address_t * lcl, ip4_address_t * rmt,
                                  u16 lcl_port, u16 rmt_port, u8 proto,
                                  u32 my_thread_index)
{
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv4.value, my_thread_index);

      return tp_vfts[s->session_type].get_connection (s->connection_index,
                                                      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener4 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&smm->v4_half_open_hash, &kv4);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv4.value & 0xFFFFFFFF);

  return 0;
}

transport_connection_t *
stream_session_lookup_transport6 (session_manager_main_t *smm,
                                  ip6_address_t * lcl, ip6_address_t * rmt,
                                  u16 lcl_port, u16 rmt_port, u8 proto,
                                  u32 my_thread_index)
{
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv6.value, my_thread_index);

      return tp_vfts[s->session_type].get_connection (s->connection_index,
                                                      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener6 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&smm->v6_half_open_hash, &kv6);
  if (rv == 0)
    return tp_vfts[s->session_type].get_half_open (kv6.value & 0xFFFFFFFF);

  return 0;
}

always_inline int
application_api_queue_is_full (application_t *app)
{
  unix_shared_memory_queue_t * q;

  /* builtin servers are always OK */
  if (app->api_client_index == ~0)
    return 0;

  q = vl_api_client_index_to_input_queue (app->api_client_index);
  if (!q)
    return 1;

  if (q->cursize == q->maxsize)
    return 1;
  return 0;
}

void
session_manager_get_segment_info (u32 index, u8 **name, u32 *size)
{
  svm_fifo_segment_private_t *s;
  s = svm_fifo_get_segment (index);
  *name = s->h->segment_name;
  *size = s->ssvm.ssvm_size;
}


always_inline int
session_manager_add_segment_i (session_manager_main_t *smm,
                               session_manager_t *sm,
                               u32 segment_size, u8 *segment_name)
{
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  int rv;

  memset (ca, 0, sizeof (*ca));

  ca->segment_name = (char *)segment_name;
  ca->segment_size = segment_size;

  rv = svm_fifo_segment_create (ca);
  if (rv)
    {
      clib_warning("svm_fifo_segment_create ('%s', %d) failed",
                   ca->segment_name, ca->segment_size);
      vec_free (segment_name);
      return -1;
    }

  vec_add1(sm->segment_indices, ca->new_segment_index);

  return 0;
}

static int
session_manager_add_segment (session_manager_main_t *smm, session_manager_t *sm)
{
  u8 *segment_name;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  u32 add_segment_size;
  u32 default_segment_size = 128 << 10;

  memset(ca, 0, sizeof(*ca));
  segment_name = format (0, "%d-%d%c", getpid (),
                         smm->unique_segment_name_counter++, 0);
  add_segment_size =
      sm->add_segment_size ? sm->add_segment_size : default_segment_size;

  return session_manager_add_segment_i (smm, sm, add_segment_size,
                                        segment_name);
}

static int
session_manager_add_first_segment (session_manager_main_t *smm,
                                   session_manager_t *sm, u32 segment_size,
                                   u8 **segment_name)
{
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  memset (ca, 0, sizeof (*ca));
  *segment_name = format (0, "%d-%d%c", getpid (),
                         smm->unique_segment_name_counter++, 0);
  return session_manager_add_segment_i (smm, sm, segment_size, *segment_name);
}

static void
session_manager_del (session_manager_main_t *smm, session_manager_t *sm)
{
  u32 *deleted_sessions = 0;
  u32 *deleted_thread_indices = 0;
  int i, j;

  /* Across all fifo segments used by the server */
  for (j = 0; j < vec_len(sm->segment_indices); j++)
    {
      svm_fifo_segment_private_t * fifo_segment;
      svm_fifo_t **fifos;
      /* Vector of fifos allocated in the segment */
      fifo_segment = svm_fifo_get_segment (sm->segment_indices[j]);
      fifos = (svm_fifo_t **) fifo_segment->h->fifos;

      /*
       * Remove any residual sessions from the session lookup table
       * Don't bother deleting the individual fifos, we're going to
       * throw away the fifo segment in a minute.
       */
      for (i = 0; i < vec_len(fifos); i++)
        {
          svm_fifo_t * fifo;
          u32 session_index, thread_index;
          stream_session_t * session;

          fifo = fifos[i];
          session_index = fifo->server_session_index;
          thread_index = fifo->server_thread_index;

          session = pool_elt_at_index(smm->sessions[thread_index],
                                      session_index);

          /* Add to the deleted_sessions vector (once!) */
          if (!session->is_deleted)
            {
              session->is_deleted = 1;
              vec_add1(deleted_sessions, session - smm->sessions[thread_index]);
              vec_add1(deleted_thread_indices, thread_index);
            }
        }

      for (i = 0; i < vec_len(deleted_sessions); i++)
        {
          stream_session_t * session;

          session = pool_elt_at_index(smm->sessions[deleted_thread_indices[i]],
                                      deleted_sessions[i]);
          stream_session_table_del (smm, session);
          pool_put(smm->sessions[deleted_thread_indices[i]], session);
        }

      vec_reset_length(deleted_sessions);
      vec_reset_length(deleted_thread_indices);

      svm_fifo_segment_delete (fifo_segment);
    }

  vec_free(deleted_sessions);
  vec_free(deleted_thread_indices);
}

int
session_manager_allocate_session_fifos (session_manager_main_t *smm,
                                        session_manager_t *sm,
                                        svm_fifo_t **server_rx_fifo,
                                        svm_fifo_t **server_tx_fifo,
                                        u32 *fifo_segment_index,
                                        u8 *added_a_segment)
{
  svm_fifo_segment_private_t *fifo_segment;
  u32 fifo_size, default_fifo_size = 8192 /* TODO config */;
  int i;

  *added_a_segment = 0;

  /* Allocate svm fifos */
  ASSERT(vec_len(sm->segment_indices));

 again:
  for (i = 0; i < vec_len (sm->segment_indices); i++)
    {
      *fifo_segment_index = sm->segment_indices[i];
      fifo_segment = svm_fifo_get_segment (*fifo_segment_index);

      fifo_size = sm->rx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_rx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      fifo_size = sm->tx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_tx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      if (*server_rx_fifo == 0)
        {
          /* This would be very odd, but handle it... */
          if (*server_tx_fifo != 0)
            {
              svm_fifo_segment_free_fifo (fifo_segment, *server_tx_fifo);
              *server_tx_fifo = 0;
            }
          continue;
        }
      if (*server_tx_fifo == 0)
        {
          if (*server_rx_fifo != 0)
            {
              svm_fifo_segment_free_fifo (fifo_segment, *server_rx_fifo);
              *server_rx_fifo = 0;
            }
          continue;
        }
      break;
    }

  /* See if we're supposed to create another segment */
  if (*server_rx_fifo == 0)
    {
      if (sm->add_segment)
        {
          if (*added_a_segment)
            {
              clib_warning ("added a segment, still cant allocate a fifo");
              return URI_INPUT_ERROR_NEW_SEG_NO_SPACE;
            }

          if (session_manager_add_segment (smm, sm))
            return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;

          *added_a_segment = 1;
          goto again;
        }
      else
        return URI_INPUT_ERROR_NO_SPACE;
    }
  return 0;
}

int
stream_session_create_i (session_manager_main_t *smm, application_t *app,
                         transport_connection_t *tc, stream_session_t **ret_s)
{
  int rv;
  svm_fifo_t *server_rx_fifo = 0, *server_tx_fifo = 0;
  u32 fifo_segment_index;
  u32 pool_index, seg_size;
  stream_session_t *s;
  u64 value;
  u32 thread_index = tc->thread_index;
  session_manager_t *sm = application_get_session_manager (smm, app);
  u8 segment_added;
  u8 *seg_name;

  /* Check the API queue */
  if (app->mode == APP_SERVER && application_api_queue_is_full (app))
    return URI_INPUT_ERROR_API_QUEUE_FULL;

  if ((rv = session_manager_allocate_session_fifos (smm, sm, &server_rx_fifo,
                                                    &server_tx_fifo,
                                                    &fifo_segment_index,
                                                    &segment_added)))
    return rv;

  if (segment_added && app->mode == APP_SERVER)
    {
      /* Send an API message to the external server, to map new segment */
      ASSERT(app->add_segment_callback);

      session_manager_get_segment_info (fifo_segment_index, &seg_name,
                                        &seg_size);
      if (app->add_segment_callback (app, seg_name, seg_size))
        return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
    }

  /* Create the session */
  pool_get(smm->sessions[thread_index], s);
  memset (s, 0, sizeof(*s));

  /* Initialize backpointers */
  pool_index = s - smm->sessions[thread_index];
  server_rx_fifo->server_session_index = pool_index;
  server_rx_fifo->server_thread_index = thread_index;

  server_tx_fifo->server_session_index = pool_index;
  server_tx_fifo->server_thread_index = thread_index;

  s->server_rx_fifo = server_rx_fifo;
  s->server_tx_fifo = server_tx_fifo;

  /* Initialize state machine, such as it is... */
  s->session_type = app->session_type;
  s->session_state = SESSION_STATE_CONNECTING;
  s->server_index = app - smm->applications;
  s->server_segment_index = fifo_segment_index;
  s->session_thread_index = thread_index;
  s->session_index = pool_index;

  /* Attach transport to session */
  s->connection_index = tc->c_index;

  /* Attach session to transport */
  tc->s_index = s->session_index;

  /* Add to the main lookup table */
  value = (((u64) thread_index) << 32) | (u64) s->session_index;
  stream_session_table_add_for_tc (smm, app->session_type, tc, value);

  *ret_s = s;

  return 0;
}

/*
 * Enqueue data for delivery to session peer. Does not notify peer of enqueue
 * event but on request can queue notification events for later delivery by
 * calling stream_server_flush_enqueue_events().
 *
 * @param tc Transport connection which is to be enqueued data
 * @param data Data to be enqueued
 * @param len Length of data to be enqueued
 * @param queue_event Flag to indicate if peer is to be notified or if event
 *                    is to be queued. The former is useful when more data is
 *                    enqueued and only one event is to be generated.
 * @return Number of bytes enqueued or a negative value if enqueueing failed.
 */
int
stream_session_enqueue_data (transport_connection_t *tc, u8 *data, u16 len,
                             u8 queue_event)
{
  stream_session_t *s;
  int enqueued;

  s = stream_session_get (tc->s_index, tc->thread_index);

  /* Make sure there's enough space left. We might've filled the pipes */
  if (PREDICT_FALSE(len > svm_fifo_max_enqueue (s->server_rx_fifo)))
    return -1;

  enqueued = svm_fifo_enqueue_nowait2 (s->server_rx_fifo, s->pid, len, data);

  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_manager_main_t *smm = vnet_get_session_manager_main ();
      u32 thread_index = s->session_thread_index;
      u32 my_enqueue_epoch = smm->current_enqueue_epoch[thread_index];

      if (s->enqueue_epoch != my_enqueue_epoch)
        {
          s->enqueue_epoch = my_enqueue_epoch;
          vec_add1(smm->session_indices_to_enqueue_by_thread[thread_index],
                   s - smm->sessions[thread_index]);
        }
    }

  return enqueued;
}

/** Check if we have space in rx fifo to push more bytes */
u8
stream_session_no_space (transport_connection_t *tc, u32 thread_index,
                         u16 data_len)
{
  stream_session_t *s = stream_session_get (tc->c_index, thread_index);

  if (PREDICT_FALSE(s->session_state != SESSION_STATE_READY))
    return 1;

  if (data_len > svm_fifo_max_enqueue (s->server_rx_fifo))
    return 1;

  return 0;
}

u32
stream_session_peek_bytes (transport_connection_t *tc, u8 *buffer, u32 offset,
                           u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->server_tx_fifo, s->pid, offset, max_bytes, buffer);
}

u32
stream_session_dequeue_drop (transport_connection_t *tc, u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->server_tx_fifo, s->pid, max_bytes);
}

/**
 * Notify session peer that new data has been enqueued.
 *
 * @param s Stream session for which the event is to be generated.
 * @param block Flag to indicate if call should block if event queue is full.
 *
 * @return 0 on succes or negative number if failed to send notification.
 */
int
stream_session_enqueue_notify (stream_session_t *s0, u8 block)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  application_t *ss0;
  fifo_event_t evt;
  unix_shared_memory_queue_t * q;
  static u32 serial_number;

  /* Get session's server */
  ss0 = pool_elt_at_index (smm->applications, s0->server_index);

  /* Fabricate event */
  evt.fifo = s0->server_rx_fifo;
  evt.event_type = FIFO_EVENT_SERVER_RX;
  evt.event_id = serial_number++;
  evt.enqueue_length = svm_fifo_max_dequeue (s0->server_rx_fifo);

  /* Add event to server's event queue */
  q = ss0->event_queue;

  /* Based on request block (or not) for lack of space */
  if (block || PREDICT_TRUE (q->cursize < q->maxsize))
    unix_shared_memory_queue_add (ss0->event_queue, (u8 *)&evt,
                                  0 /* do wait for mutex */);
  else
    return -1;

  if (1)
    {
      ELOG_TYPE_DECLARE(e) =
        {
          .format = "evt-enqueue: id %d length %d",
          .format_args = "i4i4",
        };
      struct { u32 data[2];} * ed;
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->data[0] = evt.event_id;
      ed->data[1] = evt.enqueue_length;
    }

  return 0;
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
int
session_manager_flush_enqueue_events (u32 my_thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 *session_indices_to_enqueue;
  int i, errors = 0;

  session_indices_to_enqueue =
      smm->session_indices_to_enqueue_by_thread[my_thread_index];

  for (i = 0; i < vec_len(session_indices_to_enqueue); i++)
    {
      stream_session_t * s0;

      /* Get session */
      s0 = stream_session_get (session_indices_to_enqueue[i], my_thread_index);
      if (stream_session_enqueue_notify (s0, 0 /* don't block */))
        {
          errors++;
        }
    }

  vec_reset_length(session_indices_to_enqueue);

  smm->session_indices_to_enqueue_by_thread[my_thread_index] =
      session_indices_to_enqueue;

  /* Increment enqueue epoch for next round */
  smm->current_enqueue_epoch[my_thread_index] ++;

  return errors;
}

void
application_del (session_manager_main_t *smm, application_t *app)
{
  api_main_t *am = &api_main;
  void *oldheap;
  session_manager_t *sm;

  if (app->mode == APP_SERVER)
    {
      sm = application_get_session_manager (smm, app);
      session_manager_del (smm, sm);
    }

  /* Free the event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);
  if (app->event_queue)
    unix_shared_memory_queue_free (app->event_queue);
  svm_pop_heap (oldheap);

  pool_put (smm->applications, app);
}

application_t *
application_new (session_manager_main_t *smm, application_type_t type,
                 stream_session_type_t sst)
{
  api_main_t *am = &api_main;
  application_t *app;
  void *oldheap;
  session_manager_t *sm;

  pool_get(smm->applications, app);
  memset(app, 0, sizeof(*app));

  /* Allocate event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  /* Allocate server event queue */
  if (app->event_queue == 0)
    {
      app->event_queue = unix_shared_memory_queue_init (
          128 /* nels $$$$ config */, sizeof(fifo_event_t),
          0 /* consumer pid */,
          0 /* (do not) send signal when queue non-empty */);
    }

  svm_pop_heap (oldheap);

  /* If a server, allocate session manager */
  if (type == APP_SERVER)
    {
      pool_get (smm->session_managers, sm);
      memset (sm, 0, sizeof(*sm));

      app->session_manager_index = sm - smm->session_managers;
    }

  app->mode = type;
  app->server_index = app - smm->applications;
  app->session_type = sst;

  return app;
}

/*
 * Start listening on server's ip/port pair for requested transport.
 *
 * Creates a 'dummy' stream session with state LISTENING to be used in session
 * lookups, prior to establishing connection. Requests transport to build
 * it's own specific listening connection.
 */
int
stream_server_listen (session_manager_main_t *smm, application_t *server,
                      ip46_address_t *ip, u16 port)
{
  stream_session_t *s;
  transport_connection_t *tc;
  u32 tci;

  pool_get(smm->listen_sessions[server->session_type], s);
  memset(s, 0, sizeof(*s));

  s->session_type = server->session_type;
  s->session_state = SESSION_STATE_LISTENING;
  s->server_index = server->server_index;
  s->session_index = s - smm->listen_sessions[server->session_type];

  /* Transport bind/listen  */
  tci = tp_vfts[server->session_type].bind (smm->vlib_main, s->session_index, ip,
                                        port);

  /* Attach transport to session */
  s->connection_index = tci;
  tc = tp_vfts[server->session_type].get_listener (tci);

  server->listen_session_index = s->session_index;

  /* Add to the main lookup table */
  stream_session_table_add_for_tc (smm, s->session_type, tc, s->session_index);

  return 0;
}

void
stream_server_listen_stop (session_manager_main_t *smm, application_t *ss)
{
  stream_session_t *listener;
  transport_connection_t *tc;

  listener = pool_elt_at_index(smm->listen_sessions[ss->session_type],
                               ss->listen_session_index);

  tc = tp_vfts[ss->session_type].get_listener (
      listener->connection_index);
  stream_session_table_del_for_tc (smm, listener->session_type, tc);

  tp_vfts[ss->session_type].unbind (smm->vlib_main,
                                    listener->connection_index);
  pool_put(smm->listen_sessions[ss->session_type], listener);
}

int
connect_server_add_segment_cb (application_t *ss, char * segment_name,
                               u32 segment_size)
{
  /* Does exactly nothing, but die */
  ASSERT (0);
  return 0;
}

void
connect_manager_init (session_manager_main_t *smm, u8 session_type)
{
  session_manager_t *sm;
  u32 connect_fifo_size = 8<<10; /* Config?*/
  u32 default_segment_size = 1<<20;

  pool_get(smm->session_managers, sm);
  memset (sm, 0, sizeof (*sm));

  sm->add_segment_size = default_segment_size;
  sm->rx_fifo_size = connect_fifo_size;
  sm->tx_fifo_size = connect_fifo_size;
  sm->add_segment = 1;

  session_manager_add_segment (smm, sm);
  smm->connect_manager_index[session_type] = sm - smm->session_managers;
}

int
session_connected_callback (application_t *client, stream_session_t *s,
                            unix_shared_memory_queue_t * vpp_event_queue,
                            u8 code) __attribute__((weak));

int
session_connected_callback (application_t *client, stream_session_t *s,
                            unix_shared_memory_queue_t * vpp_event_queue,
                            u8 code)
{
  clib_warning("STUB");
  return -1;
}

void
stream_session_connect_notify (transport_connection_t *tc, u8 sst, u8 code)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *app;
  stream_session_t *new_s;
  unix_shared_memory_queue_t *vpp_event_queue;
  u64 value;

  value = stream_session_half_open_lookup (smm, &tc->lcl_ip, &tc->rmt_ip,
                                           tc->lcl_port, tc->rmt_port,
                                           tc->proto);
  if (value == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      clib_warning ("This can't be good!");
      return;
    }

  /* Allocate the client app */
  app = application_new (smm, APP_CLIENT, sst);
  app->session_manager_index = smm->connect_manager_index[sst];
  app->api_client_index = value >> 32;
  app->session_connected_callback = session_connected_callback;

  /* Create new session (server segments are allocated if needed) */
  if (stream_session_create_i (smm, app, tc, &new_s))
    return;

  /* Allocate vpp event queue for this thread if needed */
  vpp_session_event_queue_allocate (smm, tc->thread_index);

  /* Prepare for callback */
  vpp_event_queue = smm->vpp_event_queues[tc->thread_index];

  /* Notify client */
  app->session_connected_callback (app, new_s, vpp_event_queue, code);

  /* Cleanup session lookup */
  stream_session_half_open_table_del (smm, sst, tc);
}

void
stream_session_accept_notify (transport_connection_t *tc)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *ss;
  stream_session_t *s;

  s = stream_session_get (tc->s_index, tc->thread_index);

  /* Get session's server */
  ss = pool_elt_at_index(smm->applications, s->server_index);

  /* Shoulder-tap the server */
  ss->session_accept_callback (ss, s, smm->vpp_event_queues[tc->thread_index]);
}

void
stream_session_reset_notify (transport_connection_t *tc)
{
  /* TODO */
}

int
redirect_connect_uri_callback (u32 api_client_index, void *mp) __attribute__((weak));

int redirect_connect_uri_callback (u32 api_client_index, void *mp)
{
  clib_warning ("STUB");
  return -1;
}

static int
application_connect_to_local_server (application_t *ss,
                                     ip46_address_t *ip46_address, void *mp,
                                     u8 is_ip4)
{
  ip4_fib_t * fib;
  u32 fib_index;
  ip4_fib_mtrie_leaf_t leaf0;
  ip4_address_t * dst_addr0;
  u32 lbi0;
  const load_balance_t * lb0;
  const dpo_id_t *dpo0;
  ip4_fib_mtrie_t * mtrie0;

  /* Look up <address>, and see if we hit a local adjacency */
  if (is_ip4)
    {
      /* $$$$$ move this to a fib fcn. */
      /* Default FIB ($$$for the moment) */
      fib_index = ip4_fib_index_from_table_id (0);
      ASSERT (fib_index != ~0);
      fib = ip4_fib_get (fib_index);

      dst_addr0 = &ip46_address->ip4;
      mtrie0 = &fib->mtrie;
      leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 0);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 1);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);

      if (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY)
        goto done;

      lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
      lb0 = load_balance_get (lbi0);

      /* Local (interface) adjs are not load-balanced... */
      if (lb0->lb_n_buckets > 1)
        goto done;

      dpo0 = load_balance_get_bucket_i (lb0, 0);
      /* $$$$$ end move this to a fib fcn. */
    }
  else
    {
      /* TODO */
      goto done;
    }

  if (dpo0->dpoi_type == DPO_RECEIVE)
    {
      int rv;
      /* redirect to the server */
      rv = redirect_connect_uri_callback (ss->api_client_index, mp);
      return rv;
    }

 done:
  return VNET_API_ERROR_INVALID_VALUE;
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
stream_session_accept (transport_connection_t *tc, u32 listener_index, u8 sst,
                       u8 notify)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *ss;
  stream_session_t *s, *ls;
  unix_shared_memory_queue_t *vpp_event_queue;

  int rv;

  /* Find the server */
  ls = pool_elt_at_index (smm->listen_sessions[sst], listener_index);
  ss = pool_elt_at_index (smm->applications, ls->server_index);

  if ((rv = stream_session_create_i (smm, ss, tc, &s)))
    return rv;

  /* Allocate vpp event queue for this thread if needed */
  vpp_session_event_queue_allocate (smm, tc->thread_index);

  /* Shoulder-tap the server */
  if (notify)
    {
      vpp_event_queue = smm->vpp_event_queues[tc->thread_index];
      ss->session_accept_callback (ss, s, vpp_event_queue);
    }

  return 0;
}

void
stream_session_delete (session_manager_main_t *smm, stream_session_t * s)
{
  int rv;
  svm_fifo_segment_private_t * fifo_segment;
  u32 my_thread_index = s->session_thread_index;

  /* delete from the main lookup table */
  rv = stream_session_table_del (smm, s);

  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  /* recover the fifo segment */
  fifo_segment = svm_fifo_get_segment (s->server_segment_index);

  svm_fifo_segment_free_fifo (fifo_segment, s->server_rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_tx_fifo);

  tp_vfts[s->session_type].delete (s->connection_index,
                                                 my_thread_index);
  pool_put (smm->sessions[my_thread_index], s);
}


void
stream_session_open (session_manager_main_t *smm, u8 sst, ip46_address_t *addr,
                     u16 port_host_byte_order, u32 api_client_index)
{
  transport_connection_t *tc;
  u32 tci;
  u64 value;

  /* Ask transport to open connection */
  tci = tp_vfts[sst].open (addr, port_host_byte_order);

  /* Get transport connection */
  tc = tp_vfts[sst].get_half_open (tci);

  /* Store api_client_index and transport connection index */
  value = (((u64) api_client_index) << 32) | (u64) tc->c_index;

  /* Add to the half-open lookup table */
  stream_session_half_open_table_add (smm, sst, tc, value);
}

void
stream_session_close (session_manager_main_t *smm, application_t *ss)
{
  /* TODO */
}

/**** fifo uri */

u32
vnet_bind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

u32
vnet_unbind_fifo_uri (uri_main_t *um, u16 port)
{
  return 0;
}

int
vnet_connect_fifo_uri (char *uri, u32 api_client_index, u64 * options,
                       char *segment_name_arg, u32 * segment_name_length)
{
  uri_main_t * um = &uri_main;
  uri_bind_table_entry_t * e;
  uword * p;

  ASSERT(segment_name_length);

  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);

  if (!p)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  e = pool_elt_at_index (um->fifo_bind_table, p[0]);

  *segment_name_length = vec_len(e->segment_name);
  memcpy (segment_name_arg, e->segment_name, *segment_name_length);
  e->connect_client_index = api_client_index;

  return 0;
}

/**** end fifo URI */

/**
 * unformat a vnet URI
 *
 * fifo://name
 * tcp://ip46-addr:port
 * udp://ip46-addr:port
 *
 * u8 ip46_address[16];
 * u16  port_in_host_byte_order;
 * stream_session_type_t sst;
 * u8 *fifo_name;
 *
 * if (unformat (input, "%U", unformat_vnet_uri, &ip46_address,
 *              &sst, &port, &fifo_name))
 *  etc...
 *
 */

uword
unformat_vnet_uri (unformat_input_t * input, va_list * args)
{
  ip46_address_t * address = va_arg (*args, ip46_address_t *);
  stream_session_type_t * sst = va_arg (*args, stream_session_type_t *);
  u16 * port = va_arg(*args, u16 *);
  u8 ** fifo_name = va_arg(*args, u8 **);
  u8 * name = 0;

  *fifo_name = 0;

  if (unformat (input, "tcp://%U/%d", unformat_ip4_address, &address->ip4,
                port))
    {
      *sst = SESSION_TYPE_IP4_TCP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip4_address, &address->ip4,
                port))
    {
      *sst = SESSION_TYPE_IP4_UDP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip6_address, &address->ip6,
                port))
    {
      *sst = SESSION_TYPE_IP6_UDP;
      return 1;
    }
  if (unformat (input, "tcp://%U/%d", unformat_ip6_address, &address->ip6,
                port))
    {
      *sst = SESSION_TYPE_IP6_TCP;
      return 1;
    }
  if (unformat (input, "fifo://%s", name))
    {
      *fifo_name = name;
      *sst = SESSION_TYPE_FIFO;
      return 1;
    }

  return 0;
}
uri_bind_table_entry_t *
fifo_bind_table_lookup (uri_main_t *um, char *uri)
{
  uword *p;
  p = hash_get_mem (um->uri_bind_table_entry_by_name, uri);
  if (!p)
     return 0;

  return pool_elt_at_index (um->fifo_bind_table, p[0]);
}

void
fifo_bind_table_add (uri_main_t *um, u8 *uri, u8 *server_name,
                    u8 *segment_name, u32 api_client_index, u32 accept_cookie)
{
  uri_bind_table_entry_t * e;

  pool_get(um->fifo_bind_table, e);
  memset(e, 0, sizeof(*e));

  e->bind_name = uri;
  e->server_name = server_name;
  e->segment_name = segment_name;
  e->bind_client_index = api_client_index;
  e->accept_cookie = accept_cookie;

  hash_set_mem(um->uri_bind_table_entry_by_name, e->bind_name,
               e - um->fifo_bind_table);
}

int
fifo_bind_table_del (uri_main_t *um, uri_bind_table_entry_t *e)
{

  hash_unset_mem(um->uri_bind_table_entry_by_name, e->bind_name);
  pool_put(um->fifo_bind_table, e);

  return 0;
}

int
vnet_bind_uri (vnet_bind_uri_args_t *a)
{
  uri_main_t *um = &uri_main;
  vl_api_registration_t *regp;
  u8 * segment_name = 0;
  u8 * server_name;
  session_manager_main_t *smm = &session_manager_main;
  application_t *app = 0;
  u16 port_number_host_byte_order;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;
  unformat_input_t _input, *input= &_input;
  ip46_address_t ip46_address;
  u8 *fifo_name;
  session_manager_t *sm;
  int rv;

  ASSERT(a->uri && a->segment_name_length);

  /* Make sure ??? */
  a->uri = (char *)format (0, "%s%c", a->uri, 0);

  if (fifo_bind_table_lookup (um, a->uri))
    return VNET_API_ERROR_ADDRESS_IN_USE;

  unformat_init_string (input, a->uri, strlen (a->uri));
  /* If the URI doesn't parse, return an error */
  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address,
                 &sst, &port_number_host_byte_order, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* External client? */
  if (a->api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (a->api_client_index);
      ASSERT(regp);
      server_name = format (0, "%s%c", regp->name, 0);
    }
  else
    server_name = format (0, "<internal>%c", 0);

  /*
   * $$$$ lookup client by api client index, to see if we're already
   * talking to this client about some other port
   */

  if (sst == SESSION_TYPE_FIFO)
    goto uri_bind;

  /* Allocate and initialize stream server */
  app = application_new (smm, APP_SERVER, sst);
  sm = application_get_session_manager (smm, app);

  /* Add first segment */
  if ((rv = session_manager_add_first_segment (smm, sm, a->segment_size,
                                               &segment_name)))
    {
      /* If it failed, cleanup */
      application_del (smm, app);
      return rv;
    }

  /* Initialize stream server */
  app->api_client_index = a->api_client_index;
  app->flags = a->options[URI_OPTIONS_FLAGS];

  /* Callbacks */
  app->session_accept_callback = a->send_session_create_callback;
  app->session_delete_callback = stream_session_delete;
  app->session_clear_callback = a->send_session_clear_callback;
  app->builtin_server_rx_callback = a->builtin_server_rx_callback;
  app->add_segment_callback = a->add_segment_callback;

  /* Setup session manager */
  sm->add_segment_size = a->options[URI_OPTIONS_ADD_SEGMENT_SIZE];
  sm->rx_fifo_size = a->options[URI_OPTIONS_RX_FIFO_SIZE];
  sm->tx_fifo_size = a->options[URI_OPTIONS_TX_FIFO_SIZE];
  sm->add_segment = 1;

  /* Setup listen path down to transport */
  stream_server_listen (smm, app, &ip46_address, port_number_host_byte_order);

 uri_bind:

  fifo_bind_table_add (um, (u8 *)a->uri, server_name, segment_name,
                      a->api_client_index, a->accept_cookie);

  /*
   * Return values
   */

  ASSERT (vec_len(segment_name) <= 128);
  a->segment_name_length = vec_len(segment_name);
  memcpy (a->segment_name, segment_name, a->segment_name_length);
  a->server_event_queue_address = (u64) app->event_queue;

  vec_free (fifo_name);

  return 0;
}

int
vnet_unbind_uri (char * uri, u32 api_client_index)
{
  uri_main_t * um = &uri_main;
  session_manager_main_t * smm = &session_manager_main;
  application_t * ss;
  vl_api_registration_t *regp;
  u16 port_number_host_byte_order;
  stream_session_type_t sst = SESSION_TYPE_N_TYPES;
  unformat_input_t _input, *input = &_input;
  ip46_address_t ip46_address;
  u8 *fifo_name;
  uri_bind_table_entry_t *e;

  ASSERT(uri);

  /* Clean out the uri->server name mapping */
  e = fifo_bind_table_lookup (um, uri);
  if (!e)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  unformat_init_string (input, uri, strlen (uri));
  /* If the URI doesn't parse, return an error */
  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address, &sst,
                 &port_number_host_byte_order, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* External client? */
  if (api_client_index != ~0)
    {
      regp = vl_api_client_index_to_registration (api_client_index);
      ASSERT(regp);
    }

  /*
   * Find the stream_server_t corresponding to the api client
   * $$$$ maybe add a hash table? There may only be three or four...
   */
  pool_foreach(ss, smm->applications, (
  {
    if (ss->api_client_index == api_client_index)
    goto found;
  }));

  /* Better never happen... */
  return VNET_API_ERROR_INVALID_VALUE_2;

  found:

  /* Clear the listener */
  if (sst != SESSION_TYPE_FIFO)
    stream_server_listen_stop (smm, ss);

  application_del (smm, ss);

  fifo_bind_table_del (um, e);

  return 0;
}

int
vnet_connect_uri (char *uri, u32 api_client_index, u64 *options,
                  char *segment_name, u32 *name_length, void *mp)
{
  session_manager_main_t *smm = &session_manager_main;
  unformat_input_t _input, *input= &_input;
  ip46_address_t ip46_address;
  u16 port;
  stream_session_type_t sst;
  u8 *fifo_name, is_ip4 = 0;
  stream_session_t *listener;
  application_t *ss;
  int rv;

  ASSERT(uri);

  /* TODO XXX connects table */

  memset(&ip46_address, 0, sizeof(ip46_address_t));
  unformat_init_string (input, uri, strlen (uri));

  if (!unformat (input, "%U", unformat_vnet_uri, &ip46_address,
                &sst, &port, &fifo_name))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* FIFO do its thing and return */
  if (SESSION_TYPE_FIFO == sst)
    {
      rv = vnet_connect_fifo_uri (uri, api_client_index, options, segment_name,
                                  name_length);
      vec_free(fifo_name);
      return rv;
    }

  /*
   * Figure out if connecting to a local server
   */

  listener = stream_session_lookup_listener (&ip46_address,
                                             clib_host_to_net_u16 (port), sst);

  /* Find the server */
  if (listener)
    {
      ss = pool_elt_at_index(smm->applications, listener->server_index);

      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (SESSION_TYPE_IP4_UDP == sst || SESSION_TYPE_IP4_TCP == sst)
        is_ip4 = 1;

      if (ss->flags & (URI_OPTIONS_FLAGS_USE_FIFO == 1))
        return application_connect_to_local_server (ss, &ip46_address, mp,
                                                      is_ip4);
    }

  /*
   * Not connecting to a local server. Create regular session
   */

  /* Allocate connect session manager if needed */
  if (smm->connect_manager_index[sst] == INVALID_INDEX)
    connect_manager_init(smm, sst);

  /* Notify transport */
  stream_session_open (smm, sst, &ip46_address, port, api_client_index);

  /* TODO */
  return VNET_API_ERROR_INVALID_VALUE;
}

int
vnet_disconnect_uri (u32 client_index, u32 session_index, u32 thread_index)
{
  session_manager_main_t * smm = &session_manager_main;
  stream_session_t * session;
  stream_session_t * pool;

  if (thread_index >= vec_len (smm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  session = pool_elt_at_index (smm->sessions[thread_index],
                               session_index);

  switch (session->session_type)
    {
    case SESSION_TYPE_IP4_UDP:
      stream_session_delete (smm, session);
      break;

    default:
      return VNET_API_ERROR_UNIMPLEMENTED;
    }
  return 0;
}

void
uri_register_transport (u8 type, const transport_proto_vft_t *vft)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();

  vec_validate (tp_vfts, type);
  tp_vfts[type] = *vft;

  /* If an offset function is provided, then peek instead of dequeue */
  smm->session_rx_fns[type] =
      (vft->rx_fifo_offset) ? session_fifo_rx_peek : session_fifo_rx_dequeue;
}

transport_proto_vft_t *
uri_get_transport (u8 type)
{
  if (type >= vec_len (tp_vfts))
    return 0;
  return &tp_vfts[type];
}

static clib_error_t *
uri_init (vlib_main_t * vm)
{
  uri_main_t * um = &uri_main;

  um->uri_bind_table_entry_by_name = hash_create_string (0, sizeof (uword));
  um->vlib_main = vm;
  um->vnet_main = vnet_get_main();
  return 0;
}

VLIB_INIT_FUNCTION (uri_init);

static clib_error_t *
session_manager_main_init (vlib_main_t * vm)
{
  u32 num_threads;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  session_manager_main_t * smm = &session_manager_main;
  int i;

  smm->vlib_main = vm;
  smm->vnet_main = vnet_get_main();

  num_threads = 1 /* main thread */ + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* $$$ config parameters */
  svm_fifo_segment_init (0x200000000ULL /* first segment base VA */,
                         20 /* timeout in seconds */);

  /* configure per-thread ** vectors */
  vec_validate (smm->sessions, num_threads - 1);
  vec_validate (smm->session_indices_to_enqueue_by_thread, num_threads-1);
  vec_validate (smm->tx_buffers, num_threads - 1);
  vec_validate (smm->fifo_events, num_threads - 1);
  vec_validate (smm->evts_partially_read, num_threads - 1);
  vec_validate (smm->current_enqueue_epoch, num_threads - 1);
  vec_validate (smm->vpp_event_queues, num_threads - 1);
  vec_validate (smm->copy_buffers, num_threads - 1);

  /* $$$$ preallocate hack config parameter */
  for (i = 0; i < 200000; i++)
    {
      stream_session_t * ss;
      pool_get (smm->sessions[0], ss);
      memset (ss, 0, sizeof (*ss));
    }

  for (i = 0; i < 200000; i++)
      pool_put_index (smm->sessions[0], i);

  clib_bihash_init_16_8 (&smm->v4_session_hash, "v4 session table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);
  clib_bihash_init_48_8 (&smm->v6_session_hash, "v6 session table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);

  clib_bihash_init_16_8 (&smm->v4_half_open_hash, "v4 half-open table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);
  clib_bihash_init_48_8 (&smm->v6_half_open_hash, "v6 half-open table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);

  for (i = 0; i < SESSION_TYPE_N_TYPES; i++)
    smm->connect_manager_index[i] = INVALID_INDEX;

  return 0;
}

VLIB_INIT_FUNCTION (session_manager_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
