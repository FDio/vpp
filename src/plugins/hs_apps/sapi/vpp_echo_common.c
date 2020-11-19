/*
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

#include <stdio.h>
#include <signal.h>

#include <hs_apps/sapi/vpp_echo_common.h>

char *echo_fail_code_str[] = {
#define _(sym, str) str,
  foreach_echo_fail_code
#undef _
};

/*
 *
 *  Format functions
 *
 */

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
	  || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x",
		      (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

/* Format an IP46 address. */
u8 *
format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ?
    format (s, "%U", format_ip4_address, &ip46->ip4) :
    format (s, "%U", format_ip6_address, &ip46->ip6);
}

u8 *
format_api_error (u8 * s, va_list * args)
{
  echo_main_t *em = &echo_main;
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (em->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

void
init_error_string_table ()
{
  echo_main_t *em = &echo_main;
  em->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (em->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (em->error_string_by_error_number, 99, "Misc");
}

u8 *
echo_format_session (u8 * s, va_list * args)
{
  echo_session_t *session = va_arg (*args, echo_session_t *);

  return format (s, "%U 0x%lx S[%u]", echo_format_session_type,
		 session->session_type, session->vpp_session_handle,
		 session->session_index);
}

u8 *
echo_format_session_type (u8 * s, va_list * args)
{
  u32 session_type = va_arg (*args, u32);
  switch (session_type)
    {
    case ECHO_SESSION_TYPE_QUIC:
      return format (s, "Qsession");
    case ECHO_SESSION_TYPE_STREAM:
      return format (s, "Stream");
    case ECHO_SESSION_TYPE_LISTEN:
      return format (s, "Lsession");
    default:
      break;
    }
  return format (s, "BadSession");
}

u8 *
echo_format_session_state (u8 * s, va_list * args)
{
  u32 session_state = va_arg (*args, u32);
  switch (session_state)
    {
    case ECHO_SESSION_STATE_INITIAL:
      return format (s, "ECHO_SESSION_STATE_INITIAL (%u)", session_state);
    case ECHO_SESSION_STATE_READY:
      return format (s, "ECHO_SESSION_STATE_READY (%u)", session_state);
    case ECHO_SESSION_STATE_AWAIT_CLOSING:
      return format (s, "ECHO_SESSION_STATE_AWAIT_CLOSING (%u)",
		     session_state);
    case ECHO_SESSION_STATE_AWAIT_DATA:
      return format (s, "ECHO_SESSION_STATE_AWAIT_DATA (%u)", session_state);
    case ECHO_SESSION_STATE_CLOSING:
      return format (s, "ECHO_SESSION_STATE_CLOSING (%u)", session_state);
    case ECHO_SESSION_STATE_CLOSED:
      return format (s, "ECHO_SESSION_STATE_CLOSED (%u)", session_state);
    default:
      break;
    }
  return format (s, "unknown session state (%u)", session_state);
}

u8 *
echo_format_app_state (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);
  if (state == STATE_START)
    return format (s, "STATE_START (%u)", state);
  if (state == STATE_ATTACHED)
    return format (s, "STATE_ATTACHED (%u)", state);
  if (state == STATE_ATTACHED_NO_CERT)
    return format (s, "STATE_ATTACHED_NO_CERT (%u)", state);
  if (state == STATE_LISTEN)
    return format (s, "STATE_LISTEN (%u)", state);
  if (state == STATE_READY)
    return format (s, "STATE_READY (%u)", state);
  if (state == STATE_DATA_DONE)
    return format (s, "STATE_DATA_DONE (%u)", state);
  if (state == STATE_DISCONNECTED)
    return format (s, "STATE_DISCONNECTED (%u)", state);
  if (state == STATE_DETACHED)
    return format (s, "STATE_DETACHED (%u)", state);
  else
    return format (s, "unknown state (%u)", state);
}

uword
echo_unformat_close (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "Y"))
    *a = ECHO_CLOSE_F_ACTIVE;
  else if (unformat (input, "N"))
    *a = ECHO_CLOSE_F_NONE;
  else if (unformat (input, "W"))
    *a = ECHO_CLOSE_F_PASSIVE;
  else
    return 0;
  return 1;
}

uword
echo_unformat_timing_event (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "start"))
    *a = ECHO_EVT_START;
  else if (unformat (input, "qconnected"))
    *a = ECHO_EVT_LAST_QCONNECTED;
  else if (unformat (input, "qconnect"))
    *a = ECHO_EVT_FIRST_QCONNECT;
  else if (unformat (input, "sconnected"))
    *a = ECHO_EVT_LAST_SCONNECTED;
  else if (unformat (input, "sconnect"))
    *a = ECHO_EVT_FIRST_SCONNECT;
  else if (unformat (input, "lastbyte"))
    *a = ECHO_EVT_LAST_BYTE;
  else if (unformat (input, "exit"))
    *a = ECHO_EVT_EXIT;
  else
    return 0;
  return 1;
}

u8 *
echo_format_bytes_per_sec (u8 * s, va_list * args)
{
  f64 bps = va_arg (*args, f64) * 8;
  if (bps > 1e9)
    return format (s, "%.3f Gb/s", bps / 1e9);
  else if (bps > 1e6)
    return format (s, "%.3f Mb/s", bps / 1e6);
  else if (bps > 1e3)
    return format (s, "%.3f Kb/s", bps / 1e3);
  else
    return format (s, "%.3f b/s", bps);
}

u8 *
echo_format_timing_event (u8 * s, va_list * args)
{
  u32 timing_event = va_arg (*args, u32);
  if (timing_event == ECHO_EVT_START)
    return format (s, "start");
  if (timing_event == ECHO_EVT_FIRST_QCONNECT)
    return format (s, "qconnect");
  if (timing_event == ECHO_EVT_LAST_QCONNECTED)
    return format (s, "qconnected");
  if (timing_event == ECHO_EVT_FIRST_SCONNECT)
    return format (s, "sconnect");
  if (timing_event == ECHO_EVT_LAST_SCONNECTED)
    return format (s, "sconnected");
  if (timing_event == ECHO_EVT_LAST_BYTE)
    return format (s, "lastbyte");
  if (timing_event == ECHO_EVT_EXIT)
    return format (s, "exit");
  else
    return format (s, "unknown timing event");
}

uword
unformat_transport_proto (unformat_input_t * input, va_list * args)
{
  u32 *proto = va_arg (*args, u32 *);
  if (unformat (input, "tcp"))
    *proto = TRANSPORT_PROTO_TCP;
  else if (unformat (input, "TCP"))
    *proto = TRANSPORT_PROTO_TCP;
  else if (unformat (input, "udp"))
    *proto = TRANSPORT_PROTO_UDP;
  else if (unformat (input, "UDP"))
    *proto = TRANSPORT_PROTO_UDP;
  else if (unformat (input, "tls"))
    *proto = TRANSPORT_PROTO_TLS;
  else if (unformat (input, "TLS"))
    *proto = TRANSPORT_PROTO_TLS;
  else if (unformat (input, "quic"))
    *proto = TRANSPORT_PROTO_QUIC;
  else if (unformat (input, "QUIC"))
    *proto = TRANSPORT_PROTO_QUIC;
  else
    return 0;
  return 1;
}

u8 *
format_transport_proto (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  switch (transport_proto)
    {
    case TRANSPORT_PROTO_TCP:
      s = format (s, "TCP");
      break;
    case TRANSPORT_PROTO_UDP:
      s = format (s, "UDP");
      break;
    case TRANSPORT_PROTO_NONE:
      s = format (s, "NONE");
      break;
    case TRANSPORT_PROTO_TLS:
      s = format (s, "TLS");
      break;
    case TRANSPORT_PROTO_QUIC:
      s = format (s, "QUIC");
      break;
    case TRANSPORT_PROTO_DTLS:
      s = format (s, "DTLS");
      break;
    default:
      s = format (s, "UNKNOWN");
      break;
    }
  return s;
}

uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

uword
unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t *result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
	hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
	hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
	n_colon++;
      else
	{
	  unformat_put_input (input);
	  break;
	}

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
	return 0;

      if (hex_digit < 16)
	{
	  hex_quad = (hex_quad << 4) | hex_digit;

	  /* Hex quad must fit in 16 bits. */
	  if (n_hex_digits >= 4)
	    return 0;

	  n_colon = 0;
	  n_hex_digits++;
	}

      /* Save position of :: */
      if (n_colon == 2)
	{
	  /* More than one :: ? */
	  if (double_colon_index < ARRAY_LEN (hex_quads))
	    return 0;
	  double_colon_index = n_hex_quads;
	}

      if (n_colon > 0 && n_hex_digits > 0)
	{
	  hex_quads[n_hex_quads++] = hex_quad;
	  hex_quad = 0;
	  n_hex_digits = 0;
	}
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;

  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
	word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

	for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
	  hex_quads[n_zero + i] = hex_quads[i];

	for (i = 0; i < n_zero; i++)
	  hex_quads[double_colon_index + i] = 0;

	n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

uword
unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip = va_arg (*args, ip46_address_t *);

  if (unformat (input, "%U", unformat_ip4_address, &ip->ip4))
    ;
  else if (unformat (input, "%U", unformat_ip6_address, &ip->ip6))
    ;
  else
    return 0;
  return 1;
}

u8 *
echo_format_crypto_engine (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);
  if (state == CRYPTO_ENGINE_MBEDTLS)
    return format (s, "mbedtls");
  if (state == CRYPTO_ENGINE_OPENSSL)
    return format (s, "openssl");
  if (state == CRYPTO_ENGINE_PICOTLS)
    return format (s, "picotls");
  if (state == CRYPTO_ENGINE_VPP)
    return format (s, "vpp");
  else
    return format (s, "unknown crypto engine");
}

uword
echo_unformat_crypto_engine (unformat_input_t * input, va_list * args)
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


/*
 *
 *  End of format functions
 *
 */

void
echo_session_handle_add_del (echo_main_t * em, u64 handle, u32 sid)
{
  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  if (sid == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (3, "hash_unset(0x%lx)", handle);
      hash_unset (em->session_index_by_vpp_handles, handle);
    }
  else
    {
      ECHO_LOG (3, "hash_set(0x%lx) S[%d]", handle, sid);
      hash_set (em->session_index_by_vpp_handles, handle, sid);
    }
  clib_spinlock_unlock (&em->sid_vpp_handles_lock);
}

echo_session_t *
echo_session_new (echo_main_t * em)
{
  /* thread safe new prealloced session
   * see echo_session_prealloc */
  return pool_elt_at_index (em->sessions,
			    clib_atomic_fetch_add (&em->nxt_available_sidx,
						   1));
}

int
echo_send_rpc (echo_main_t * em, void *fp, echo_rpc_args_t * args)
{
  svm_msg_q_msg_t msg;
  echo_rpc_msg_t *evt;
  if (PREDICT_FALSE (svm_msg_q_lock (em->rpc_msq_queue)))
    {
      ECHO_FAIL (ECHO_FAIL_RPC_SIZE, "RPC lock failed");
      return -1;
    }
  if (PREDICT_FALSE (svm_msg_q_ring_is_full (em->rpc_msq_queue, 0)))
    {
      svm_msg_q_unlock (em->rpc_msq_queue);
      ECHO_FAIL (ECHO_FAIL_RPC_SIZE, "RPC ring is full");
      return -2;
    }
  msg = svm_msg_q_alloc_msg_w_ring (em->rpc_msq_queue, 0);
  evt = (echo_rpc_msg_t *) svm_msg_q_msg_data (em->rpc_msq_queue, &msg);
  evt->fp = fp;
  clib_memcpy (&evt->args, args, sizeof (evt->args));

  svm_msg_q_add_and_unlock (em->rpc_msq_queue, &msg);
  return 0;
}

echo_session_t *
echo_get_session_from_handle (echo_main_t * em, u64 handle)
{
  uword *p;
  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  p = hash_get (em->session_index_by_vpp_handles, handle);
  clib_spinlock_unlock (&em->sid_vpp_handles_lock);
  if (!p)
    {
      ECHO_LOG (2, "unknown handle 0x%lx", handle);
      return 0;
    }
  return pool_elt_at_index (em->sessions, p[0]);
}

int
wait_for_state_change (echo_main_t * em, connection_state_t state,
		       f64 timeout)
{
  f64 end_time = clib_time_now (&em->clib_time) + timeout;
  while (!timeout || clib_time_now (&em->clib_time) < end_time)
    {
      if (em->state == state)
	return 0;
      if (em->time_to_stop)
	return 1;
    }
  ECHO_LOG (2, "timeout waiting for %U", echo_format_app_state, state);
  return -1;
}

void
echo_notify_event (echo_main_t * em, echo_test_evt_t e)
{
  if (em->timing.events_sent & e)
    return;
  if (em->timing.start_event == e)
    em->timing.start_time = clib_time_now (&em->clib_time);
  else if (em->timing.end_event == e)
    em->timing.end_time = clib_time_now (&em->clib_time);
  em->timing.events_sent |= e;
}

void
echo_session_print_stats (echo_main_t * em, echo_session_t * session)
{
  f64 deltat = clib_time_now (&em->clib_time) - session->start;
  ECHO_LOG (1, "Session 0x%x done in %.6fs RX[%.4f] TX[%.4f] Gbit/s\n",
	    session->vpp_session_handle, deltat,
	    (session->bytes_received * 8.0) / deltat / 1e9,
	    (session->bytes_sent * 8.0) / deltat / 1e9);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
