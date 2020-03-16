/*
 * Copyright(c) 2018 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#define _BSD_SOURCE
#include <endian.h>

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>

#include "pfcp.h"

#if CLIB_DEBUG > 1
#define pfcp_debug clib_warning
#else
#define pfcp_debug(...)				\
  do { } while (0)
#endif

/*************************************************************************/

u8 *
format_flags (u8 * s, va_list * args)
{
  uint64_t flags = va_arg (*args, uint64_t);
  const char **atoms = va_arg (*args, const char **);
  int first = 1;

  s = format (s, "[");
  for (int i = 0; i < 64 && atoms[i] != NULL; i++)
    {
      if (!ISSET_BIT (flags, i))
	continue;

      if (!first)
	s = format (s, ",");

      s = format (s, "%s", atoms[i]);
      first = 0;
    }
  s = format (s, "]");

  return s;
}

u8 *
format_enum (u8 * s, va_list * args)
{
  uint64_t e = va_arg (*args, uint64_t);
  const char **atoms = va_arg (*args, const char **);
  ssize_t size = va_arg (*args, ssize_t);

  if (e >= size || atoms[e] == NULL)
    return format (s, "undef(%u)", e);

  return format (s, "%s", atoms[e]);
}

u8 *
format_network_instance (u8 * s, va_list * args)
{
  u8 *label = va_arg (*args, u8 *);
  u8 i = 0;

  if (!label)
    return format (s, "invalid");

  if (*label > 64)
    {
      vec_append (s, label);
      return s;
    }

  while (i < vec_len (label))
    {
      if (i != 0)
	vec_add1 (s, '.');
      vec_add (s, label + i + 1, label[i]);
      i += label[i] + 1;
    }

  return s;
}

/*************************************************************************/

static const char *msg_desc[] = {
  [PFCP_HEARTBEAT_REQUEST] = "Heartbeat Request",
  [PFCP_HEARTBEAT_RESPONSE] = "Heartbeat Response",
  [PFCP_PFD_MANAGEMENT_REQUEST] = "PFD Management Request",
  [PFCP_PFD_MANAGEMENT_RESPONSE] = "PFD Management Response",
  [PFCP_ASSOCIATION_SETUP_REQUEST] = "Association Setup Request",
  [PFCP_ASSOCIATION_SETUP_RESPONSE] = "Association Setup Response",
  [PFCP_ASSOCIATION_UPDATE_REQUEST] = "Association Update Request",
  [PFCP_ASSOCIATION_UPDATE_RESPONSE] = "Association Update Response",
  [PFCP_ASSOCIATION_RELEASE_REQUEST] = "Association Release Request",
  [PFCP_ASSOCIATION_RELEASE_RESPONSE] = "Association Release Response",
  [PFCP_VERSION_NOT_SUPPORTED_RESPONSE] = "Version Not Supported Response",
  [PFCP_NODE_REPORT_REQUEST] = "Node Report Request",
  [PFCP_NODE_REPORT_RESPONSE] = "Node Report Response",
  [PFCP_SESSION_SET_DELETION_REQUEST] = "Session Set Deletion Request",
  [PFCP_SESSION_SET_DELETION_RESPONSE] = "Session Set Deletion Response",
  [PFCP_SESSION_ESTABLISHMENT_REQUEST] = "Session Establishment Request",
  [PFCP_SESSION_ESTABLISHMENT_RESPONSE] = "Session Establishment Response",
  [PFCP_SESSION_MODIFICATION_REQUEST] = "Session Modification Request",
  [PFCP_SESSION_MODIFICATION_RESPONSE] = "Session Modification Response",
  [PFCP_SESSION_DELETION_REQUEST] = "Session Deletion Request",
  [PFCP_SESSION_DELETION_RESPONSE] = "Session Deletion Response",
  [PFCP_SESSION_REPORT_REQUEST] = "Session Report Request",
  [PFCP_SESSION_REPORT_RESPONSE] = "Session Report Response",
};

u8 *
format_pfcp_msg_hdr (u8 * s, va_list * args)
{
  pfcp_header_t *pfcp = va_arg (*args, pfcp_header_t *);
  u8 type = pfcp->type;

  if (type < ARRAY_LEN (msg_desc) && msg_desc[type])
    return format (s, "PFCP: V:%d,S:%d,MP:%d, %s (%d), Length: %d.",
		   pfcp->version, pfcp->s_flag, pfcp->mp_flag,
		   msg_desc[type], type, clib_net_to_host_u16 (pfcp->length));
  else
    return format (s, "PFCP: V:%d,S:%d,MP:%d, %d, Length: %d.",
		   pfcp->version, pfcp->s_flag, pfcp->mp_flag,
		   type, clib_net_to_host_u16 (pfcp->length));
}

/*************************************************************************/

/* message construction helpers */

#define set_msg_hdr_version(V,VER) ((pfcp_header_t *)(V))->version = (VER)
#define set_msg_hdr_type(V,TYPE) ((pfcp_header_t *)(V))->type = (TYPE)
#define set_msg_hdr_seq(V,S)						\
  do {									\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[0] = (S >> 16) &0xff;	\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[1] = (S >> 8) &0xff;	\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[2] = S &0xff;		\
  } while (0)
#define copy_msg_hdr_seq(V,S)						\
  clib_memcpy(((pfcp_header_t *)(V))->msg_hdr.sequence, (S)->msg_hdr.sequence, \
	      sizeof(S->msg_hdr.sequence))
#define set_msg_hdr_length(V,LEN) ((pfcp_header_t *)(V))->length =  htons((LEN))

#define put_msg_response(V,REQ,TYPE,P)		\
  do {						\
    set_msg_hdr_version((V), 1);		\
    set_msg_hdr_type((V), (TYPE));		\
    copy_msg_hdr_seq((V), (REQ));		\
    (P) = NODE_MSG_HDR_LEN;			\
  } while (0)

#define set_ie_hdr_type(V,TYPE,P)  ((pfcp_ie_t *)&(V)[(P)])->type = htons((TYPE))
#define set_ie_hdr_length(V,LEN,P) ((pfcp_ie_t *)&(V)[(P)])->length = htons((LEN))
#define put_ie_hdr(V,TYPE,LEN,P)		\
  do {						\
    set_ie_hdr_type(V,TYPE,P);			\
    set_ie_hdr_length(V,LEN,P);			\
    (P) += sizeof(pfcp_ie_t);			\
  } while (0)
#define finalize_ie(V,HDR,P) set_ie_hdr_length((V), (P) - (HDR) - sizeof(pfcp_ie_t), (HDR))

#define set_ie_vendor_hdr_type(V,TYPE,VEND,P)			\
  ((pfcp_ie_vendor_t *)&(V)[(P)])->type = htons((TYPE))
#define set_ie_vendor_hdr_length(V,LEN,P)			\
  ((pfcp_ie_vendor_t *)&(V)[(P)])->length = htons((LEN))
#define set_ie_vendor_hdr_vendor(V,VEND,P)			\
  ((pfcp_ie_vendor_t *)&(V)[(P)])->vendor = htons((VEND))
#define put_ie_vendor_hdr(V,TYPE,VEND,LEN,P)			\
  do {								\
    set_ie_vendor_hdr_type((V),(TYPE) & 0x8000,(P));		\
    set_ie_vendor_hdr_length((V),(LEN),(P));			\
    set_ie_vendor_hdr_vendor((V),(VEND),(P));			\
    (P) += sizeof(pfcp_ie_vendor_t);				\
  } while (0)

#define put_u8(V,I)				\
  do {						\
    *((u8 *)&(V)[_vec_len((V))]) = (I);		\
    _vec_len((V)) += sizeof(u8);		\
  } while (0)

#define get_u8(V)				\
  ({u8 *_V = (V);				\
    (V)++;					\
    *_V; })

#define put_u16(V,I)				\
  do {						\
    *((u16 *)&(V)[_vec_len((V))]) = htons((I));	\
    _vec_len((V)) += sizeof(u16);		\
  } while (0)

#define get_u16(V)				\
  ({u16 *_V = (u16 *)(V);			\
    (V) += sizeof(u16);				\
    ntohs(*_V); })

#define put_u16_little(V,I)						\
  do {									\
    *((u16 *)&(V)[_vec_len((V))]) = clib_host_to_little_u16((I));	\
    _vec_len((V)) += sizeof(u16);					\
  } while (0)

#define get_u16_little(V)				\
  ({u16 *_V = (u16 *)(V);				\
    (V) += sizeof(u16);					\
    clib_little_to_host_u16(*_V); })

#define put_u24(V,I)					\
  do {							\
    (V)[_vec_len((V))] = (I) >> 16;			\
    (V)[_vec_len((V)) + 1] = ((I) >> 8) & 0xff;		\
    (V)[_vec_len((V)) + 2] = (I) & 0xff;		\
    _vec_len((V)) += 3;					\
  } while (0)

#define get_u24(V)						\
  ({u32 _V = ((V)[0] << 16) | ((V)[1] << 8) | ((V)[2]);		\
    (V) += 3;							\
    _V; })

#define put_u32(V,I)				\
  do {						\
    *((u32 *)&(V)[_vec_len((V))]) = htonl((I));	\
    _vec_len((V)) += sizeof(u32);		\
  } while (0)

#define get_u32(V)				\
  ({u32 *_V = (u32 *)(V);			\
    (V) += sizeof(u32);				\
    ntohl(*_V); })

#define put_u64(V,I)					\
  do {							\
    *((u64 *)&(V)[_vec_len((V))]) = htobe64((I));	\
    _vec_len((V)) += sizeof(u64);			\
  } while (0)

#define get_u64(V)				\
  ({u64 *_V = (u64 *)(V);			\
    (V) += sizeof(u64);				\
    be64toh(*_V); })

typedef union
{
  f64 _float;
  u64 _uint;
} f64_u64_t;

#if 0

#define put_f64(V,I)						\
  do {								\
    *((u64 *)&(V)[_vec_len((V))]) = htobe64(*(u64 *)&(I));	\
    _vec_len((V)) += sizeof(u64);				\
  } while (0)

#define get_f64(V)					\
  ({f64_u64_t _V = { ._uint = be64toh(*(u64 *)(V))};	\
    (V) += sizeof(f64);					\
    _V._float; })

#endif

#define get_ip4(IP,V)				\
  do {						\
    (IP).as_u32 = *(u32 *)(V);			\
    (V) += 4;					\
  } while (0)

#define put_ip4(V,IP)				\
  do {						\
    u8 *_t = vec_end((V));			\
    *(u32 *)_t = (IP).as_u32;			\
    _vec_len((V)) += 4;				\
  } while (0)

#define get_ip6(IP,V)				\
  do {						\
    (IP).as_u64[0] = ((u64 *)(V))[0];		\
    (IP).as_u64[1] = ((u64 *)(V))[1];		\
    (V) += 16;					\
  } while (0)

#define put_ip6(V,IP)				\
  do {						\
    u8 *_t = vec_end((V));			\
    ((u64 *)_t)[0] = (IP).as_u64[0];		\
    ((u64 *)_t)[1] = (IP).as_u64[1];		\
    _vec_len((V)) += 16;			\
} while (0)

#define put_ip46_ip4(V,IP)			\
  put_ip4(V, (IP).ip4)

#define get_ip46_ip4(IP,V)				\
  do {							\
    ip46_address_set_ip4(&(IP), (ip4_address_t *)(V));	\
    (V) += 4;						\
  } while (0)

#define put_ip46_ip6(V,IP)			\
  put_ip6(V, (IP).ip6)

#define get_ip46_ip6(IP,V)			\
  get_ip6((IP).ip6, (V))

#define get_vec(VEC,L,V)			\
  do {						\
    vec_reset_length ((VEC));			\
    vec_add ((VEC), (V), (L));			\
    (V) += (L);					\
  } while (0)

#define finalize_msg(V,P)			\
  do {						\
    set_msg_hdr_length(V,(P) - 4);		\
    _vec_len((V)) = (P);			\
  } while (0)

/* generic IEs */

static u8 *
format_u8_ie (u8 * s, va_list * args)
{
  u8 *v = va_arg (*args, u8 *);

  return format (s, "%u", *v);
}

static int
decode_u8_ie (u8 * data, u16 length, void *p)
{
  u8 *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8 (data);

  return 0;
}

static int
encode_u8_ie (void *p, u8 ** vec)
{
  u8 *v = p;

  put_u8 (*vec, *v);
  return 0;
}

static u8 *
format_u16_ie (u8 * s, va_list * args)
{
  u16 *v = va_arg (*args, u16 *);

  return format (s, "%u", *v);
}

static int
decode_u16_ie (u8 * data, u16 length, void *p)
{
  u16 *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16 (data);

  return 0;
}

static int
encode_u16_ie (void *p, u8 ** vec)
{
  u16 *v = p;

  put_u16 (*vec, *v);
  return 0;
}

static int
decode_u16_little_ie (u8 * data, u16 length, void *p)
{
  u16 *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16_little (data);

  return 0;
}

static int
encode_u16_little_ie (void *p, u8 ** vec)
{
  u16 *v = p;

  put_u16_little (*vec, *v);
  return 0;
}

static u8 *
format_u32_ie (u8 * s, va_list * args)
{
  u32 *v = va_arg (*args, u32 *);

  return format (s, "%u", *v);
}

static int
decode_u32_ie (u8 * data, u16 length, void *p)
{
  u32 *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32 (data);

  return 0;
}

static int
encode_u32_ie (void *p, u8 ** vec)
{
  u32 *v = p;

  put_u32 (*vec, *v);
  return 0;
}

static u8 *
format_simple_vec_ie (u8 * s, va_list * args)
{
  u8 **v = va_arg (*args, u8 **);

  return format (s, "%v", *v);
}

static int
decode_simple_vec_ie (u8 * data, u16 length, void *p)
{
  u8 **v = p;

  vec_reset_length (*v);
  vec_add (*v, data, length);

  return 0;
}

static int
encode_simple_vec_ie (void *p, u8 ** vec)
{
  u8 **v = p;

  vec_append (*vec, *v);

  return 0;
}

static void
free_simple_vec_ie (void *p)
{
  u8 **v = p;

  vec_free (*v);
}

static u8 *
format_volume_ie (u8 * s, va_list * args)
{
  pfcp_volume_ie_t *v = va_arg (*args, pfcp_volume_ie_t *);

  return format (s, "T:%d,U:%d,D:%d", v->total, v->ul, v->dl);
}

static int
decode_volume_ie (u8 * data, u16 length, void *p)
{
  pfcp_volume_ie_t *v = (pfcp_volume_ie_t *) p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->fields = get_u8 (data) & PFCP_VOLUME_VOLUME;

  if (length < 1 + __builtin_popcount (v->fields) * sizeof (u64))
    return PFCP_CAUSE_INVALID_LENGTH;

  if (v->fields & PFCP_VOLUME_TOVOL)	/* Total Volume */
    v->total = get_u64 (data);
  if (v->fields & PFCP_VOLUME_ULVOL)	/* Uplink Volume */
    v->ul = get_u64 (data);
  if (v->fields & PFCP_VOLUME_DLVOL)	/* Downlink Volume */
    v->dl = get_u64 (data);

  return 0;
}

static int
encode_volume_ie (void *p, u8 ** vec)
{
  pfcp_volume_ie_t *v = (pfcp_volume_ie_t *) p;

  put_u8 (*vec, v->fields);

  if (v->fields & PFCP_VOLUME_TOVOL)	/* Total Volume */
    put_u64 (*vec, v->total);
  if (v->fields & PFCP_VOLUME_ULVOL)	/* Uplink Volume */
    put_u64 (*vec, v->ul);
  if (v->fields & PFCP_VOLUME_DLVOL)	/* Downlink Volume */
    put_u64 (*vec, v->dl);

  return 0;
}

static u8 *
format_time_stamp (u8 * s, va_list * args)
{
  u32 *v = va_arg (*args, u32 *);
  struct timeval tv = {.tv_sec = *v,.tv_usec = 0 };

  return format (s, "%U", format_timeval, 0, &tv);
}

static int
decode_time_stamp_ie (u8 * data, u16 length, void *p)
{
  u32 *v = (u32 *) p;

  if (length != 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = ntohl (*(u32 *) data);
  if (*v & 0x80000000)
    *v -= 2208988800;		/* use base: 1-Jan-1900 @ 00:00:00 UTC */
  else
    *v += 2085978496;		/* use base: 7-Feb-2036 @ 06:28:16 UTC */

  return 0;
}

static int
encode_time_stamp_ie (void *p, u8 ** vec)
{
  u32 *v = (u32 *) p;

  if (*v >= 2085978496)
    put_u32 (*vec, *v - 2085978496);
  else
    put_u32 (*vec, *v + 2208988800);

  return 0;
}

static u8 *
format_timer_ie (u8 * s, va_list * args)
{
  pfcp_timer_ie_t *v = va_arg (*args, pfcp_timer_ie_t *);

  switch (v->unit)
    {
    case 0:
      s = format (s, "%u secs", ((u32) v->value) * 2);
      break;
    case 2:
      s = format (s, "%u mins", ((u32) v->value) * 10);
      break;
    case 3:
      s = format (s, "%u hours", ((u32) v->value));
      break;
    case 4:
      s = format (s, "%u hours", ((u32) v->value) * 10);
      break;
    case 7:
      s = format (s, "infinite");
      break;
    default:
      s = format (s, "%u mins", v->value);
      break;
    }

  return s;
}

static int
decode_timer_ie (u8 * data, u16 length, void *p)
{
  pfcp_timer_ie_t *v = p;
  u8 t;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  t = get_u8 (data);
  v->unit = t >> 4;
  v->value = t & 0x0f;

  return 0;
}

static int
encode_timer_ie (void *p, u8 ** vec)
{
  pfcp_timer_ie_t *v = p;

  put_u8 (*vec, ((v->unit & 0x0f) << 4) | (v->value & 0x0f));

  return 0;
}

#if 0

static u8 *
format_f64_time_stamp (u8 * s, va_list * args)
{
  f64 *v = va_arg (*args, f64 *);

  return format (s, "%U", format_time_float, 0, *v);
}

static int
decode_f64_time_stamp_ie (u8 * data, u16 length, void *p)
{
  u64 *v = (u64 *) p;

  if (length != 8)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_f64 (data);

  return 0;
}

static int
encode_f64_time_stamp_ie (void *p, u8 ** vec)
{
  f64 *v = (f64 *) p;

  put_f64 (*vec, *v);

  return 0;
}

#endif

static u8 *
format_sntp_time_stamp (u8 * s, va_list * args)
{
  f64 *v = va_arg (*args, f64 *);

  return format (s, "%U", format_time_float, 0, *v);
}

static int
decode_sntp_time_stamp_ie (u8 * data, u16 length, void *p)
{
  f64 *v = (f64 *) p;

  if (length != 8)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32 (data);
  if (*v >= 2208988800ULL)
    *v -= 2208988800ULL;
  else
    *v += 2085978496ULL;

  *v += get_u32 (data) / (f64) ((u64) 1 << 32);

  return 0;
}

static int
encode_sntp_time_stamp_ie (void *p, u8 ** vec)
{
  f64 *v = (f64 *) p;
  f64 fraction, seconds;

  fraction = modf (*v, &seconds);
  if (seconds >= 2085978496ULL)
    seconds -= 2085978496ULL;
  else
    seconds += 2208988800ULL;

  put_u32 (*vec, seconds);
  put_u32 (*vec, fraction * (f64) ((u64) 1 << 32));

  return 0;
}

/* Information Elements */

#define format_cause format_u8_ie
#define decode_cause decode_u8_ie
#define encode_cause encode_u8_ie

static char *source_interface_name[] = {
  [0] = "Access",
  [1] = "Core",
  [2] = "SGi-LAN",
  [3] = "CP-Function",
};

static u8 *
format_source_interface (u8 * s, va_list * args)
{
  pfcp_source_interface_t *v = va_arg (*args, pfcp_source_interface_t *);

  return format (s, "%s", source_interface_name[*v]);
}

static int
decode_source_interface (u8 * data, u16 length, void *p)
{
  pfcp_source_interface_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8 (data) & 0x0f;
  if (*v >= 4)
    return PFCP_CAUSE_REQUEST_REJECTED;

  return 0;
}

static int
encode_source_interface (void *p, u8 ** vec)
{
  pfcp_source_interface_t *v = p;

  put_u8 (*vec, *v & 0x0f);
  return 0;
}

static u8 *
format_f_teid (u8 * s, va_list * args)
{
  pfcp_f_teid_t *v = va_arg (*args, pfcp_f_teid_t *);

  if ((v->flags & 0xf) == F_TEID_V4)
    s = format (s, "%d,IPv4:%U", v->teid, format_ip4_address, &v->ip4);
  else if ((v->flags & 0xf) == F_TEID_V6)
    s = format (s, "%d,IPv6:%U", v->teid, format_ip6_address, &v->ip6);
  else if ((v->flags & 0xf) == (F_TEID_V4 | F_TEID_V6))
    s = format (s, "%d,IPv4:%U,IPv6:%U",
		v->teid, format_ip4_address, &v->ip4,
		format_ip6_address, &v->ip6);
  else if ((v->flags & 0xf) == F_TEID_CH)
    s = format (s, "%d,CH:1", v->teid);
  else if ((v->flags & 0xf) == (F_TEID_CH | F_TEID_CHID))
    s = format (s, "%d,CH:1,CHID:%d", v->teid, v->choose_id);
  else
    s = format (s, "invalid flags: %02x", v->flags);

  return s;
}

static int
decode_f_teid (u8 * data, u16 length, void *p)
{
  pfcp_f_teid_t *v = p;

  if (length < 5)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x0f;
  v->teid = get_u32 (data);
  length -= 5;

  if (v->flags & F_TEID_CH)
    {
      if (v->flags & (F_TEID_V4 | F_TEID_V6))
	{
	  pfcp_debug ("PFCP: F-TEID with invalid flags (CH and v4/v6): %02x.",
		      v->flags);
	  return -1;
	}
    }
  else
    {
      if (v->flags & F_TEID_CHID)
	{
	  pfcp_debug
	    ("PFCP: F-TEID with invalid flags (CHID without CH): %02x.",
	     v->flags);
	  return -1;
	}
      if (!(v->flags & (F_TEID_V4 | F_TEID_V6)))
	{
	  pfcp_debug ("PFCP: F-TEID without v4/v6 address: %02x.", v->flags);
	  return -1;
	}
    }

  if (v->flags & F_TEID_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4 (v->ip4, data);
      length -= 4;
    }

  if (v->flags & F_TEID_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6 (v->ip6, data);
      length -= 16;
    }

  if (v->flags & F_TEID_CHID)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->choose_id = get_u8 (data);
    }

  return 0;
}

static int
encode_f_teid (void *p, u8 ** vec)
{
  pfcp_f_teid_t *v = p;

  put_u8 (*vec, v->flags);
  put_u32 (*vec, v->teid);
  if (v->flags & F_TEID_V4)
    put_ip4 (*vec, v->ip4);
  if (v->flags & F_TEID_V6)
    put_ip6 (*vec, v->ip6);
  if (v->flags & F_TEID_CHID)
    put_u8 (*vec, v->choose_id);
  return 0;
}

#define decode_network_instance decode_simple_vec_ie
#define encode_network_instance encode_simple_vec_ie
#define free_network_instance free_simple_vec_ie

static u8 *
format_sdf_filter (u8 * s, va_list * args)
{
  pfcp_sdf_filter_t *v = va_arg (*args, pfcp_sdf_filter_t *);

  if (v->flags & F_SDF_FD)
    s = format (s, "FD:%v,", v->flow);
  if (v->flags & F_SDF_TTC)
    s = format (s, "ToS/TC:0x%04x,", v->tos_traffic_class);
  if (v->flags & F_SDF_SPI)
    s = format (s, "SPI:%u,", v->spi);
  if (v->flags & F_SDF_FL)
    s = format (s, "FL: %u,", v->flow_label);
  if (v->flags & F_SDF_BID)
    s = format (s, "FltId: %u,", v->sdf_filter_id);

  if (v->flags)
    _vec_len (s)--;
  else
    s = format (s, "undef");

  return s;
}

static int
decode_sdf_filter (u8 * data, u16 length, void *p)
{
  pfcp_sdf_filter_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x0f;
  data++;			/* spare */
  length -= 2;

  if (v->flags & F_SDF_FD)
    {
      u16 flow_len;

      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      flow_len = get_u16 (data);
      length -= 2;

      if (length < flow_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->flow, flow_len, data);
      length -= flow_len;
    }

  if (v->flags & F_SDF_TTC)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->tos_traffic_class = get_u16 (data);
      length -= 2;
    }

  if (v->flags & F_SDF_SPI)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->spi = get_u32 (data);
      length -= 4;
    }

  if (v->flags & F_SDF_FL)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->flow_label = get_u24 (data);
      length -= 3;
    }

  if (v->flags & F_SDF_BID)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->sdf_filter_id = get_u32 (data);
      length -= 4;
    }

  return 0;
}

static int
encode_sdf_filter (void *p, u8 ** vec)
{
  pfcp_sdf_filter_t *v = p;

  put_u8 (*vec, v->flags & 0x0f);
  if (v->flags & F_SDF_FD)
    {
      put_u16 (*vec, _vec_len (v->flow));
      vec_append (*vec, v->flow);
    }
  if (v->flags & F_SDF_TTC)
    put_u16 (*vec, v->tos_traffic_class);
  if (v->flags & F_SDF_SPI)
    put_u32 (*vec, v->spi);
  if (v->flags & F_SDF_FL)
    put_u24 (*vec, v->flow_label);
  if (v->flags & F_SDF_BID)
    put_u32 (*vec, v->sdf_filter_id);

  return 0;
}

static void
free_sdf_filter (void *p)
{
  pfcp_sdf_filter_t *v = p;

  vec_free (v->flow);
}

#define format_application_id format_simple_vec_ie
#define decode_application_id decode_simple_vec_ie
#define encode_application_id encode_simple_vec_ie
#define free_application_id free_simple_vec_ie

static const char *gate_status_flags[] = {
  "OPEN",
  "CLOSED",
  NULL
};

static u8 *
format_gate_status (u8 * s, va_list * args)
{
  pfcp_gate_status_t *v = va_arg (*args, pfcp_gate_status_t *);

  return format (s, "UL:%U,DL:%U",
		 format_enum, (u64) v->ul, gate_status_flags,
		 ARRAY_LEN (gate_status_flags), format_enum, (u64) v->dl,
		 gate_status_flags, ARRAY_LEN (gate_status_flags));
}

static int
decode_gate_status (u8 * data, u16 length, void *p)
{
  pfcp_gate_status_t *v = p;
  u8 status;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  status = get_u8 (data);
  /* 2,3 - shall not be sent. If received, shall be interpreted as the value "1". */
  v->dl = !!(status & 0x03);
  v->ul = !!((status >> 2) & 0x03);

  return 0;
}

static int
encode_gate_status (void *p, u8 ** vec)
{
  pfcp_gate_status_t *v = p;

  put_u8 (*vec, (v->dl & 0x03) | ((v->ul & 0x03) << 2));

  return 0;
}

static u8 *
format_bit_rate (u8 * s, va_list * args)
{
  pfcp_bit_rate_t *v = va_arg (*args, pfcp_bit_rate_t *);

  return format (s, "UL:%u,DL:%u", v->ul, v->dl);
}

static int
decode_bit_rate (u8 * data, u16 length, void *p)
{
  pfcp_bit_rate_t *v = p;

  if (length < 8)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->ul = get_u32 (data);
  v->dl = get_u32 (data);

  return 0;
}

static int
encode_bit_rate (void *p, u8 ** vec)
{
  pfcp_bit_rate_t *v = p;

  put_u32 (*vec, v->ul);
  put_u32 (*vec, v->dl);

  return 0;
}

#define format_mbr format_bit_rate
#define decode_mbr decode_bit_rate
#define encode_mbr encode_bit_rate

#define format_gbr format_bit_rate
#define decode_gbr decode_bit_rate
#define encode_gbr encode_bit_rate

#define format_qer_correlation_id format_u32_ie
#define decode_qer_correlation_id decode_u32_ie
#define encode_qer_correlation_id encode_u32_ie

#define format_precedence format_u32_ie
#define decode_precedence decode_u32_ie
#define encode_precedence encode_u32_ie

static u8 *
format_transport_level_marking (u8 * s, va_list * args)
{
  pfcp_transport_level_marking_t *v =
    va_arg (*args, pfcp_transport_level_marking_t *);

  return format (s, "0x%04x", *v);
}

#define decode_transport_level_marking decode_u16_ie
#define encode_transport_level_marking encode_u16_ie


#define format_volume_threshold format_volume_ie
#define decode_volume_threshold decode_volume_ie
#define encode_volume_threshold encode_volume_ie

#define format_time_threshold format_u32_ie
#define decode_time_threshold decode_u32_ie
#define encode_time_threshold encode_u32_ie

#define format_monitoring_time format_time_stamp
#define decode_monitoring_time decode_time_stamp_ie
#define encode_monitoring_time encode_time_stamp_ie

#define format_subsequent_volume_threshold format_volume_ie
#define decode_subsequent_volume_threshold decode_volume_ie
#define encode_subsequent_volume_threshold encode_volume_ie

#define format_subsequent_time_threshold format_u32_ie
#define decode_subsequent_time_threshold decode_u32_ie
#define encode_subsequent_time_threshold encode_u32_ie

#define format_inactivity_detection_time format_u32_ie
#define decode_inactivity_detection_time decode_u32_ie
#define encode_inactivity_detection_time encode_u32_ie

static u8 *
format_reporting_triggers (u8 * s, va_list * args)
{
  pfcp_reporting_triggers_t *v = va_arg (*args, pfcp_reporting_triggers_t *);

  s = format (s, "PERIO:%d,VOLTH:%d,TIMTH:%d,QUHTI:%d,"
	      "START:%d,STOPT:%d,DROTH:%d,LIUSA:%d,"
	      "VOLQU:%d,TIMQU:%d,ENVCL:%d,MACAR:%d,"
	      "EVETH:%d,EVEQU:%d,IPMJL:%d",
	      !!(*v & REPORTING_TRIGGER_PERIODIC_REPORTING),
	      !!(*v & REPORTING_TRIGGER_VOLUME_THRESHOLD),
	      !!(*v & REPORTING_TRIGGER_TIME_THRESHOLD),
	      !!(*v & REPORTING_TRIGGER_QUOTA_HOLDING_TIME),
	      !!(*v & REPORTING_TRIGGER_START_OF_TRAFFIC),
	      !!(*v & REPORTING_TRIGGER_STOP_OF_TRAFFIC),
	      !!(*v & REPORTING_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD),
	      !!(*v & REPORTING_TRIGGER_LINKED_USAGE_REPORTING),
	      !!(*v & REPORTING_TRIGGER_VOLUME_QUOTA),
	      !!(*v & REPORTING_TRIGGER_TIME_QUOTA),
	      !!(*v & REPORTING_TRIGGER_ENVELOPE_CLOSURE),
	      !!(*v & REPORTING_TRIGGER_MAC_ADDRESSES_REPORTING),
	      !!(*v & REPORTING_TRIGGER_EVENT_THRESHOLD),
	      !!(*v & REPORTING_TRIGGER_EVENT_QUOTA),
	      !!(*v & REPORTING_TRIGGER_IP_MULTICAST_JOIN_LEAVE));
  return s;
}

#define decode_reporting_triggers decode_u16_little_ie
#define encode_reporting_triggers encode_u16_little_ie

static char *redir_info_type[] = {
  [REDIRECT_INFORMATION_IPv4] = "IPv4",
  [REDIRECT_INFORMATION_IPv6] = "IPv6",
  [REDIRECT_INFORMATION_HTTP] = "HTTP",
  [REDIRECT_INFORMATION_SIP] = "SIP",
};

u8 *
format_redirect_information (u8 * s, va_list * args)
{
  pfcp_redirect_information_t *n =
    va_arg (*args, pfcp_redirect_information_t *);

  switch (n->type)
    {
    case REDIRECT_INFORMATION_IPv4:
    case REDIRECT_INFORMATION_IPv6:
      s = format (s, "%s to %U", redir_info_type[n->type],
		  format_ip46_address, &n->ip, IP46_TYPE_ANY);
      break;

    case REDIRECT_INFORMATION_IPv4v6:
      s = format (s, "%s to %U/%U", redir_info_type[n->type],
		  format_ip46_address, &n->ip, IP46_TYPE_ANY,
		  format_ip46_address, &n->other_ip, IP46_TYPE_ANY);
      break;

    case REDIRECT_INFORMATION_HTTP:
    case REDIRECT_INFORMATION_SIP:
      s = format (s, "%s to %v", redir_info_type[n->type], n->uri);
      break;
    }
  return s;
}

static int
decode_redirect_information (u8 * data, u16 length, void *p)
{
  pfcp_redirect_information_t *v = p;
  unformat_input_t input;
  u16 addr_len;
  int rv;

  if (length < 3)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8 (data);
  addr_len = get_u16 (data);
  length -= 3;

  if (addr_len > length)
    return PFCP_CAUSE_INVALID_LENGTH;

  switch (v->type)
    {
    case REDIRECT_INFORMATION_IPv4:
    case REDIRECT_INFORMATION_IPv6:
      unformat_init_string (&input, (char *) data, addr_len);
      rv = unformat (&input, "%U", unformat_ip46_address, &v->ip,
		     v->type ==
		     REDIRECT_INFORMATION_IPv4 ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6);
      unformat_free (&input);

      if (!rv)
	return PFCP_CAUSE_REQUEST_REJECTED;

      break;

    case REDIRECT_INFORMATION_IPv4v6:
      unformat_init_string (&input, (char *) data, addr_len);
      rv =
	unformat (&input, "%U", unformat_ip46_address, &v->ip, IP46_TYPE_ANY);
      unformat_free (&input);

      if (!rv)
	return PFCP_CAUSE_REQUEST_REJECTED;

      data += addr_len;

      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      addr_len = get_u16 (data);
      length -= 2;

      if (addr_len > length)
	return PFCP_CAUSE_INVALID_LENGTH;

      unformat_init_string (&input, (char *) data, addr_len);
      rv =
	unformat (&input, "%U", unformat_ip46_address, &v->other_ip,
		  IP46_TYPE_ANY);
      unformat_free (&input);

      if (!rv)
	return PFCP_CAUSE_REQUEST_REJECTED;

      break;

    case REDIRECT_INFORMATION_HTTP:
    case REDIRECT_INFORMATION_SIP:
      get_vec (v->uri, addr_len, data);
      length -= addr_len;
      break;

    default:
      return PFCP_CAUSE_REQUEST_REJECTED;
    }

  return 0;
}

static int
encode_redirect_information (void *p, u8 ** vec)
{
  pfcp_redirect_information_t *v = p;
  u8 *s;

  put_u8 (*vec, v->type);

  switch (v->type)
    {
    case REDIRECT_INFORMATION_IPv4:
    case REDIRECT_INFORMATION_IPv6:
      s = format (0, "%U", format_ip46_address, &v->ip, IP46_TYPE_ANY);
      put_u16 (*vec, vec_len (s));
      vec_append (*vec, s);
      vec_free (s);
      break;

    case REDIRECT_INFORMATION_HTTP:
    case REDIRECT_INFORMATION_SIP:
      put_u16 (*vec, vec_len (v->uri));
      vec_append (*vec, v->uri);
      break;
    }

  return 0;
}

void
cpy_redirect_information (pfcp_redirect_information_t * dst,
			  pfcp_redirect_information_t * src)
{
  dst->type = src->type;

  switch (src->type)
    {
    case REDIRECT_INFORMATION_IPv4:
    case REDIRECT_INFORMATION_IPv6:
      dst->ip = src->ip;
      break;

    case REDIRECT_INFORMATION_HTTP:
    case REDIRECT_INFORMATION_SIP:
      dst->uri = vec_dup (src->uri);
      break;
    }
}

void
free_redirect_information (void *p)
{
  pfcp_redirect_information_t *v = p;

  vec_free (v->uri);
}

static u8 *
format_report_type (u8 * s, va_list * args)
{
  pfcp_report_type_t *v = va_arg (*args, pfcp_report_type_t *);

  return format (s, "DLDR:%d,USAR:%d,ERIR:%d,UPIR:%d,PMIR:%d,SESR:%d",
		 !!(*v & REPORT_TYPE_DLDR), !!(*v & REPORT_TYPE_USAR),
		 !!(*v & REPORT_TYPE_ERIR), !!(*v & REPORT_TYPE_UPIR),
		 !!(*v & REPORT_TYPE_PMIR), !!(*v & REPORT_TYPE_SESR));
}

#define decode_report_type decode_u8_ie
#define encode_report_type encode_u8_ie

#define format_offending_ie format_u16_ie
#define decode_offending_ie decode_u16_ie
#define encode_offending_ie encode_u16_ie

static u8 *
format_forwarding_policy (u8 * s, va_list * args)
{
  pfcp_forwarding_policy_t *v = va_arg (*args, pfcp_forwarding_policy_t *);

  return format (s, "%v", v->identifier);
}

static int
decode_forwarding_policy (u8 * data, u16 length, void *p)
{
  pfcp_forwarding_policy_t *v = p;
  u8 fpi_len;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  fpi_len = get_u8 (data);
  length--;

  if (fpi_len > length)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->identifier, length, data);

  return 0;
}

static int
encode_forwarding_policy (void *p, u8 ** vec)
{
  pfcp_forwarding_policy_t *v = p;

  put_u8 (*vec, vec_len (v->identifier));
  vec_append (*vec, v->identifier);

  return 0;
}

static char *destination_interface_name[] = {
  [0] = "Access",
  [1] = "Core",
  [2] = "SGi-LAN",
  [3] = "CP-Function",
  [4] = "LI Function",
  [5] = "5G VN internal",
};

static u8 *
format_destination_interface (u8 * s, va_list * args)
{
  pfcp_destination_interface_t *v =
    va_arg (*args, pfcp_destination_interface_t *);

  return format (s, "%s", destination_interface_name[*v]);
}

static int
decode_destination_interface (u8 * data, u16 length, void *p)
{
  pfcp_destination_interface_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8 (data) & 0x0f;
  if (*v >= DST_INTF_NUM)
    return PFCP_CAUSE_REQUEST_REJECTED;

  return 0;
}

static int
encode_destination_interface (void *p, u8 ** vec)
{
  pfcp_destination_interface_t *v = p;

  put_u8 (*vec, *v);
  return 0;
}

static u8 *
format_up_function_features (u8 * s, va_list * args)
{
  pfcp_up_function_features_t *v =
    va_arg (*args, pfcp_up_function_features_t *);

  return format (s,
		 "BUCP:%d,DDND:%d,DLBD:%d,TRST:%d,"
		 "FTUP:%d,PFDM:%d,HEEU:%d,TREU:%d,"
		 "EMPU:%d,PDIU:%d,UDBC:%d,QUOAC:%d,"
		 "TRACE:%d,FRRT:%d,PFDE:%d,EPFAR:%d,"
		 "DPDRA:%d,ADPDP:%d,UEIP:%d,SSET:%d,"
		 "MNOP:%d,MTE:%d,BUNDL:%d,GCOM:%d,"
		 "MPAS:%d,RTTL:%d,VTIME:%d,NORP:%d,"
		 "IPTV:%d,IP6PL:%d,TSCU:%d,MPTCP:%d,"
		 "ATSSS-LL:%d,QFQM:%d,GPQM:%d",
		 !!(*v & F_UPFF_BUCP), !!(*v & F_UPFF_DDND),
		 !!(*v & F_UPFF_DLBD), !!(*v & F_UPFF_TRST),
		 !!(*v & F_UPFF_FTUP), !!(*v & F_UPFF_PFDM),
		 !!(*v & F_UPFF_HEEU), !!(*v & F_UPFF_TREU),
		 !!(*v & F_UPFF_EMPU), !!(*v & F_UPFF_PDIU),
		 !!(*v & F_UPFF_UDBC), !!(*v & F_UPFF_QUOAC),
		 !!(*v & F_UPFF_TRACE), !!(*v & F_UPFF_FRRT),
		 !!(*v & F_UPFF_PFDE), !!(*v & F_UPFF_EPFAR),
		 !!(*v & F_UPFF_DPDRA), !!(*v & F_UPFF_ADPDP),
		 !!(*v & F_UPFF_UEIP), !!(*v & F_UPFF_SSET),
		 !!(*v & F_UPFF_MNOP), !!(*v & F_UPFF_MTE),
		 !!(*v & F_UPFF_BUNDL), !!(*v & F_UPFF_GCOM),
		 !!(*v & F_UPFF_MPAS), !!(*v & F_UPFF_RTTL),
		 !!(*v & F_UPFF_VTIME), !!(*v & F_UPFF_NORP),
		 !!(*v & F_UPFF_IPTV), !!(*v & F_UPFF_IP6PL),
		 !!(*v & F_UPFF_TSCU), !!(*v & F_UPFF_MPTCP),
		 !!(*v & F_UPFF_ATSSS_LL), !!(*v & F_UPFF_QFQM),
		 !!(*v & F_UPFF_GPQM));
}

static int
decode_up_function_features (u8 * data, u16 length, void *p)
{
  u64 *v = p;

  if (length % 2 != 0 || length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16_little (data);
  length -= 2;
  if (length == 0)
    return 0;

  *v |= (u64) get_u16_little (data) << 16;
  length -= 2;
  if (length == 0)
    return 0;

  *v |= (u64) get_u16_little (data) << 32;
  length -= 2;
  if (length == 0)
    return 0;

  // not defined in R16 (yet)
  *v |= (u64) get_u16_little (data) << 48;
  return 0;
}

static int
encode_up_function_features (void *p, u8 ** vec)
{
  u64 *v = p;

  put_u16_little (*vec, *v);
  put_u16_little (*vec, *v >> 16);
  put_u16_little (*vec, *v >> 32);

  return 0;
}

static u8 *
format_apply_action (u8 * s, va_list * args)
{
  pfcp_apply_action_t *v = va_arg (*args, pfcp_apply_action_t *);

  return format (s, "DROP:%d,FORW:%d,BUFF:%d,NOCP:%d,DUPL:%d,IPMA:%d,IPMD:%d",
		 !!(*v & F_APPLY_DROP), !!(*v & F_APPLY_FORW),
		 !!(*v & F_APPLY_BUFF), !!(*v & F_APPLY_NOCP),
		 !!(*v & F_APPLY_DUPL), !!(*v & F_APPLY_IPMA),
		 !!(*v & F_APPLY_IPMD));
}

#define decode_apply_action decode_u8_ie
#define encode_apply_action encode_u8_ie

static u8 *
format_downlink_data_service_information (u8 * s, va_list * args)
{
  pfcp_downlink_data_service_information_t *v =
    va_arg (*args, pfcp_downlink_data_service_information_t *);

  if (v->flags & F_DDSI_PPI)
    s = format (s, "PPI:0x%02x", v->paging_policy_indication);

  if (v->flags & F_DDSI_QFII)
    {
      if (v->flags & F_DDSI_PPI)
	vec_add1 (s, ',');
      s = format (s, "QFI:0x%02x", v->qfi);
    }


  return s;
}

static int
decode_downlink_data_service_information (u8 * data, u16 length, void *p)
{
  pfcp_downlink_data_service_information_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;
  length--;

  if (v->flags & F_DDSI_PPI)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->paging_policy_indication = get_u8 (data);
      length--;
    }

  if (v->flags & F_DDSI_QFII)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->qfi = get_u8 (data);
      length--;
    }

  return 0;
}

static int
encode_downlink_data_service_information (void *p, u8 ** vec)
{
  pfcp_downlink_data_service_information_t *v = p;

  put_u8 (*vec, v->flags);
  if (v->flags & F_DDSI_PPI)
    put_u8 (*vec, v->paging_policy_indication);
  if (v->flags & F_DDSI_QFII)
    put_u8 (*vec, v->qfi);

  return 0;
}

#define format_downlink_data_notification_delay format_u8_ie
#define decode_downlink_data_notification_delay decode_u8_ie
#define encode_downlink_data_notification_delay encode_u8_ie

#define format_dl_buffering_duration format_timer_ie
#define decode_dl_buffering_duration decode_timer_ie
#define encode_dl_buffering_duration encode_timer_ie


static u8 *
format_dl_buffering_suggested_packet_count (u8 * s, va_list * args)
{
  pfcp_dl_buffering_suggested_packet_count_t *v =
    va_arg (*args, pfcp_dl_buffering_suggested_packet_count_t *);

  return format (s, "%u", v);
}

static int
decode_dl_buffering_suggested_packet_count (u8 * data, u16 length, void *p)
{
  pfcp_dl_buffering_suggested_packet_count_t *v = p;

  switch (length)
    {
    case 1:
      *v = get_u8 (data);
      break;
    case 2:
      *v = get_u16 (data);
      break;
    default:
      return PFCP_CAUSE_INVALID_LENGTH;
    }

  return 0;
}

static int
encode_dl_buffering_suggested_packet_count (void *p, u8 ** vec)
{
  pfcp_dl_buffering_suggested_packet_count_t *v = p;

  if (*v < 256)
    put_u8 (*vec, *v);
  else
    put_u16 (*vec, *v);

  return 0;
}

static u8 *
format_pfcpsmreq_flags (u8 * s, va_list * args)
{
  pfcp_pfcpsmreq_flags_t *v = va_arg (*args, pfcp_pfcpsmreq_flags_t *);

  return format (s, "DROBU:%d,SNDEM:%d,QUARR:%d",
		 !!(*v & PFCPSMREQ_DROBU), !!(*v & PFCPSMREQ_SNDEM),
		 !!(*v & PFCPSMREQ_QAURR));
}

#define decode_pfcpsmreq_flags decode_u8_ie
#define encode_pfcpsmreq_flags encode_u8_ie

static u8 *
format_pfcpsrrsp_flags (u8 * s, va_list * args)
{
  pfcp_pfcpsrrsp_flags_t *v = va_arg (*args, pfcp_pfcpsrrsp_flags_t *);

  return format (s, "DROBU:%d", !!(*v & PFCPSRRSP_DROBU));
}

#define decode_pfcpsrrsp_flags decode_u8_ie
#define encode_pfcpsrrsp_flags encode_u8_ie

#define format_sequence_number format_u32_ie
#define decode_sequence_number decode_u32_ie
#define encode_sequence_number encode_u32_ie

#define format_metric format_u8_ie
#define decode_metric decode_u8_ie
#define encode_metric encode_u8_ie

#define format_timer format_timer_ie
#define decode_timer decode_timer_ie
#define encode_timer encode_timer_ie

#define format_pdr_id format_u16_ie
#define decode_pdr_id decode_u16_ie
#define encode_pdr_id encode_u16_ie

static u8 *
format_f_seid (u8 * s, va_list * args)
{
  pfcp_f_seid_t *n = va_arg (*args, pfcp_f_seid_t *);

  s = format (s, "0x%016" PRIx64 "@", n->seid);

  switch (n->flags & (IE_F_SEID_IP_ADDRESS_V4 | IE_F_SEID_IP_ADDRESS_V6))
    {
    case IE_F_SEID_IP_ADDRESS_V4:
      s = format (s, "%U", format_ip4_address, &n->ip4);
      break;

    case IE_F_SEID_IP_ADDRESS_V6:
      s = format (s, "%U", format_ip6_address, &n->ip6);
      break;

    case (IE_F_SEID_IP_ADDRESS_V4 | IE_F_SEID_IP_ADDRESS_V6):
      s =
	format (s, "%U,%U", format_ip4_address, &n->ip4, format_ip6_address,
		&n->ip6);
      break;
    }

  return s;
}

static int
decode_f_seid (u8 * data, u16 length, void *p)
{
  pfcp_f_seid_t *v = p;

  if (length < 9)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;
  if (v->flags == 0)
    {
      pfcp_debug ("PFCP: F-SEID with unsupported flags: %02x.", v->flags);
      return -1;
    }

  v->seid = get_u64 (data);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4 (v->ip4, data);
      length -= 4;
    }

  if (v->flags & IE_F_SEID_IP_ADDRESS_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6 (v->ip6, data);
    }

  return 0;
}

static int
encode_f_seid (void *p, u8 ** vec)
{
  pfcp_f_seid_t *v = p;

  put_u8 (*vec, v->flags);
  put_u64 (*vec, v->seid);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V4)
    put_ip4 (*vec, v->ip4);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V6)
    put_ip6 (*vec, v->ip6);

  return 0;
}

u8 *
format_node_id (u8 * s, va_list * args)
{
  pfcp_node_id_t *n = va_arg (*args, pfcp_node_id_t *);

  switch (n->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      s = format (s, "%U", format_ip46_address, &n->ip, IP46_TYPE_ANY);
      break;

    case NID_FQDN:
      s = format (s, "%U", format_network_instance, n->fqdn);
      break;
    }
  return s;
}

static int
decode_node_id (u8 * data, u16 length, void *p)
{
  pfcp_node_id_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8 (data) & 0x0f;
  length--;

  switch (v->type)
    {
    case NID_IPv4:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4 (v->ip, data);
      break;

    case NID_IPv6:
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6 (v->ip, data);
      break;

    case NID_FQDN:
      get_vec (v->fqdn, length, data);
      break;

    default:
      return PFCP_CAUSE_REQUEST_REJECTED;
    }

  return 0;
}

static int
encode_node_id (void *p, u8 ** vec)
{
  pfcp_node_id_t *v = p;

  put_u8 (*vec, v->type);

  switch (v->type)
    {
    case NID_IPv4:
      put_ip46_ip4 (*vec, v->ip);
      break;

    case NID_IPv6:
      put_ip46_ip6 (*vec, v->ip);
      break;

    case NID_FQDN:
      vec_append (*vec, v->fqdn);
      break;
    }

  return 0;
}

static void
free_node_id (void *p)
{
  pfcp_node_id_t *v = p;

  if (v->type == NID_FQDN)
    vec_free (v->fqdn);
}

static u8 *
format_pfd_contents (u8 * s0, va_list * args)
{
  pfcp_pfd_contents_t *v = va_arg (*args, pfcp_pfd_contents_t *);
  u8 *s = s0;

  if (vec_len (v->flow_description) > 0)
    s = format (s, "FD:%v,", v->flow_description);
  if (vec_len (v->url) > 0)
    s = format (s, "URL:%v,", v->url);
  if (vec_len (v->domain) > 0)
    s = format (s, "DN:%v,", v->domain);
  if (vec_len (v->custom) > 0)
    s =
      format (s, "CP:%U,", format_hex_bytes, v->custom, vec_len (v->custom));
  if (vec_len (v->dnp) > 0)
    s = format (s, "DNP:%v,", v->dnp);

  if (s != s0)
    _vec_len (s)--;
  else
    s = format (s, "undef");

  return s;
}

static int
decode_pfd_contents (u8 * data, u16 length, void *p)
{
  pfcp_pfd_contents_t *v = p;
  u8 flags;
  u16 len;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  flags = get_u8 (data) & F_PFD_C_MASK;
  data++;			/* spare */
  length -= 2;

  if (flags & F_PFD_C_FD)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u16 (data);
      length -= 2;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->flow_description, len, data);
      length -= len;
    }

  if (flags & F_PFD_C_URL)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u16 (data);
      length -= 2;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->url, len, data);
      length -= len;
    }

  if (flags & F_PFD_C_DN)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u16 (data);
      length -= 2;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->domain, len, data);
      length -= len;
    }

  if (flags & F_PFD_C_CP)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u16 (data);
      length -= 2;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->custom, len, data);
      length -= len;
    }

  if (flags & F_PFD_C_DNP)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u16 (data);
      length -= 2;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->dnp, len, data);
      length -= len;
    }

  return 0;
}

static int
encode_pfd_contents (void *p, u8 ** vec)
{
  pfcp_pfd_contents_t *v = p;
  u8 flags;

  flags =
    ((vec_len (v->flow_description) > 0) ? F_PFD_C_FD : 0) |
    ((vec_len (v->url) > 0) ? F_PFD_C_URL : 0) |
    ((vec_len (v->domain) > 0) ? F_PFD_C_DN : 0) |
    ((vec_len (v->custom) > 0) ? F_PFD_C_CP : 0) |
    ((vec_len (v->dnp) > 0) ? F_PFD_C_DNP : 0);

  put_u8 (*vec, flags);
  if (vec_len (v->flow_description) > 0)
    {
      put_u16 (*vec, _vec_len (v->flow_description));
      vec_append (*vec, v->flow_description);
    }
  if (vec_len (v->url) > 0)
    {
      put_u16 (*vec, _vec_len (v->url));
      vec_append (*vec, v->url);
    }
  if (vec_len (v->domain) > 0)
    {
      put_u16 (*vec, _vec_len (v->domain));
      vec_append (*vec, v->domain);
    }
  if (vec_len (v->custom) > 0)
    {
      put_u16 (*vec, _vec_len (v->custom));
      vec_append (*vec, v->custom);
    }
  if (vec_len (v->dnp) > 0)
    {
      put_u16 (*vec, _vec_len (v->dnp));
      vec_append (*vec, v->dnp);
    }

  return 0;
}

static void
free_pfd_contents (void *p)
{
  pfcp_pfd_contents_t *v = p;

  vec_free (v->flow_description);
  vec_free (v->url);
  vec_free (v->domain);
  vec_free (v->custom);
  vec_free (v->dnp);
}

static u8 *
format_measurement_method (u8 * s, va_list * args)
{
  pfcp_measurement_method_t *v = va_arg (*args, pfcp_measurement_method_t *);

  s = format (s, "DURAT:%d,VOLUM:%d,EVENT:%d",
	      !!(*v & MEASUREMENT_METHOD_DURATION),
	      !!(*v & MEASUREMENT_METHOD_VOLUME),
	      !!(*v & MEASUREMENT_METHOD_EVENT));
  return s;
}

#define decode_measurement_method decode_u8_ie
#define encode_measurement_method encode_u8_ie

static u8 *
format_usage_report_trigger (u8 * s, va_list * args)
{
  pfcp_usage_report_trigger_t *v =
    va_arg (*args, pfcp_usage_report_trigger_t *);

  s = format (s, "PERIO:%d,VOLTH:%d,TIMTH:%d,QUHTI:%d,"
	      "START:%d,STOPT:%d,DROTH:%d,IMMER:%d,"
	      "VOLQU:%d,TIMQU:%d,LIUSA:%d,TERMR:%d,"
	      "MONIT:%d,ENVCL:%d,MACAR:%d,EVETH:%d,"
	      "EVEQU:%d,TEBUR:%d,IPMJL:%d",
	      !!(*v & USAGE_REPORT_TRIGGER_PERIODIC_REPORTING),
	      !!(*v & USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD),
	      !!(*v & USAGE_REPORT_TRIGGER_TIME_THRESHOLD),
	      !!(*v & USAGE_REPORT_TRIGGER_QUOTA_HOLDING_TIME),
	      !!(*v & USAGE_REPORT_TRIGGER_START_OF_TRAFFIC),
	      !!(*v & USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC),
	      !!(*v & USAGE_REPORT_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD),
	      !!(*v & USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT),
	      !!(*v & USAGE_REPORT_TRIGGER_VOLUME_QUOTA),
	      !!(*v & USAGE_REPORT_TRIGGER_TIME_QUOTA),
	      !!(*v & USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING),
	      !!(*v & USAGE_REPORT_TRIGGER_TERMINATION_REPORT),
	      !!(*v & USAGE_REPORT_TRIGGER_MONITORING_TIME),
	      !!(*v & USAGE_REPORT_TRIGGER_ENVELOPE_CLOSURE),
	      !!(*v & USAGE_REPORT_TRIGGER_MAC_ADDRESSES_REPORTING),
	      !!(*v & USAGE_REPORT_TRIGGER_EVENT_THRESHOLD),
	      !!(*v & USAGE_REPORT_TRIGGER_EVENT_QUOTA),
	      !!(*v & USAGE_REPORT_TRIGGER_TERMINATION_BY_UP_FUNCTION_REPORT),
	      !!(*v & USAGE_REPORT_TRIGGER_IP_MULTICAST_JOIN_LEAVE));
  return s;
}

static int
decode_usage_report_trigger (u8 * data, u16 length, void *p)
{
  u64 *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16_little (data);
  length -= 2;
  if (length == 0)
    return 0;

  *v |= (u32) get_u8 (data) << 16;
  return 0;
}

static int
encode_usage_report_trigger (void *p, u8 ** vec)
{
  u32 *v = p;

  put_u16_little (*vec, *v);
  put_u8 (*vec, *v >> 16);

  return 0;
}

#define format_measurement_period format_u32_ie
#define decode_measurement_period decode_u32_ie
#define encode_measurement_period encode_u32_ie

static u8 *
format_fq_csid (u8 * s, va_list * args)
{
  pfcp_fq_csid_t *v = va_arg (*args, pfcp_fq_csid_t *);
  u16 *csid;

  switch (v->node_id_type)
    {
    case FQ_CSID_NID_IP4:
    case FQ_CSID_NID_IP6:
      s =
	format (s, "NID:%U,", format_ip46_address, &v->node_id.ip,
		IP46_TYPE_ANY);
      break;
    case FQ_CSID_NID_NID:
      s =
	format (s, "NID:MCC:%u,MNC:%u,NID:%u,", v->node_id.mcc,
		v->node_id.mnc, v->node_id.nid);
      break;
    default:
      s = format (s, "NID:undef,");
      break;
    }

  s = format (s, "CSID:[");
  vec_foreach (csid, v->csid)
  {
    s = format (s, "%u,", *csid);
  }
  if (vec_len (v->csid) != 0)
    _vec_len (s)--;
  s = format (s, "]");

  return s;
}

static int
decode_fq_csid (u8 * data, u16 length, void *p)
{
  pfcp_fq_csid_t *v = p;
  u32 id;
  u8 n;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  n = get_u8 (data);
  length--;

  v->node_id_type = n >> 4;
  n &= 0x0f;

  switch (v->node_id_type)
    {
    case FQ_CSID_NID_IP4:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4 (v->node_id.ip, data);
      length -= 4;
      break;

    case FQ_CSID_NID_IP6:
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6 (v->node_id.ip, data);
      length -= 16;
      break;

    case FQ_CSID_NID_NID:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      id = get_u32 (data);
      v->node_id.mcc = (id >> 12) / 1000;
      v->node_id.mnc = (id >> 12) % 1000;
      v->node_id.nid = id & 0x0fff;
      length -= 4;
      break;
    }

  if (length < (n * 2))
    return PFCP_CAUSE_INVALID_LENGTH;

  for (; n > 0; n--)
    {
      vec_add1 (v->csid, get_u16 (data));
      length -= 2;
    }

  return 0;
}

static int
encode_fq_csid (void *p, u8 ** vec)
{
  pfcp_fq_csid_t *v = p;
  u16 *csid;

  put_u8 (*vec, (v->node_id_type << 4) | (vec_len (v->csid) & 0x0f));

  switch (v->node_id_type)
    {
    case FQ_CSID_NID_IP4:
      put_ip46_ip4 (*vec, v->node_id.ip);
      break;

    case FQ_CSID_NID_IP6:
      put_ip46_ip6 (*vec, v->node_id.ip);
      break;

    case FQ_CSID_NID_NID:
      put_u32 (*vec,
	       (v->node_id.mcc * 1000 +
		v->node_id.mnc) << 12 | (v->node_id.nid & 0x0fff));
      break;
    }

  vec_foreach (csid, v->csid)
  {
    put_u16 (*vec, *csid);
  }

  return 0;
}

static u8 *
format_volume_measurement (u8 * s, va_list * args)
{
  pfcp_volume_measurement_t *v = va_arg (*args, pfcp_volume_measurement_t *);

  return format (s, "V:[T:%d,U:%d,D:%d],P:[T:%d,U:%d,D:%d]",
		 v->volume.total, v->volume.ul, v->volume.dl,
		 v->packets.total, v->packets.ul, v->packets.dl);
}

static int
decode_volume_measurement (u8 * data, u16 length, void *p)
{
  pfcp_volume_measurement_t *v = (pfcp_volume_measurement_t *) p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->fields = get_u8 (data) & 0x07;

  if (length < 1 + __builtin_popcount (v->fields) * sizeof (u64))
    return PFCP_CAUSE_INVALID_LENGTH;

  if (v->fields & PFCP_VOLUME_TOVOL)	/* Total Volume Measurement */
    v->volume.total = get_u64 (data);
  if (v->fields & PFCP_VOLUME_ULVOL)	/* Uplink Volume Measurement */
    v->volume.ul = get_u64 (data);
  if (v->fields & PFCP_VOLUME_DLVOL)	/* Downlink Volume Measurement */
    v->volume.dl = get_u64 (data);
  if (v->fields & PFCP_VOLUME_TONOP)	/* Total Packets Measurement */
    v->packets.total = get_u64 (data);
  if (v->fields & PFCP_VOLUME_ULNOP)	/* Uplink Packets Measurement */
    v->packets.ul = get_u64 (data);
  if (v->fields & PFCP_VOLUME_DLNOP)	/* Downlink Packets Measurement */
    v->packets.dl = get_u64 (data);

  return 0;
}

static int
encode_volume_measurement (void *p, u8 ** vec)
{
  pfcp_volume_measurement_t *v = (pfcp_volume_measurement_t *) p;

  put_u8 (*vec, v->fields);

  if (v->fields & PFCP_VOLUME_TOVOL)	/* Total Volume Measurement */
    put_u64 (*vec, v->volume.total);
  if (v->fields & PFCP_VOLUME_ULVOL)	/* Uplink Volume Measurement */
    put_u64 (*vec, v->volume.ul);
  if (v->fields & PFCP_VOLUME_DLVOL)	/* Downlink Volume Measurement */
    put_u64 (*vec, v->volume.dl);
  if (v->fields & PFCP_VOLUME_TONOP)	/* Total Packets Measurement */
    put_u64 (*vec, v->packets.total);
  if (v->fields & PFCP_VOLUME_ULNOP)	/* Uplink Packets Measurement */
    put_u64 (*vec, v->packets.ul);
  if (v->fields & PFCP_VOLUME_DLNOP)	/* Downlink Packets Measurement */
    put_u64 (*vec, v->packets.dl);

  return 0;
}

#define format_duration_measurement format_u32_ie
#define decode_duration_measurement decode_u32_ie
#define encode_duration_measurement encode_u32_ie

#define format_time_of_first_packet format_time_stamp
#define decode_time_of_first_packet decode_time_stamp_ie
#define encode_time_of_first_packet encode_time_stamp_ie

#define format_time_of_last_packet format_time_stamp
#define decode_time_of_last_packet decode_time_stamp_ie
#define encode_time_of_last_packet encode_time_stamp_ie

#define format_quota_holding_time format_u32_ie
#define decode_quota_holding_time decode_u32_ie
#define encode_quota_holding_time encode_u32_ie


static u8 *
format_dropped_dl_traffic_threshold (u8 * s, va_list * args)
{
  pfcp_dropped_dl_traffic_threshold_t *v =
    va_arg (*args, pfcp_dropped_dl_traffic_threshold_t *);

  if (v->flags & DDTT_DLPA)
    s = format (s, "DLPA:%lu", v->downlink_packets);
  if (v->flags & DDTT_DLBY)
    {
      if (v->flags & DDTT_DLPA)
	vec_add1 (s, ';');
      s = format (s, "DLBY:%lu", v->downlink_volume);
    }
  if (!v->flags)
    s = format (s, "undef");

  return s;
}

static int
decode_dropped_dl_traffic_threshold (u8 * data, u16 length, void *p)
{
  pfcp_dropped_dl_traffic_threshold_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data);
  length -= 1;

  if (v->flags & DDTT_DLPA)
    {
      if (length < 8)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->downlink_packets = get_u64 (data);
      length -= 8;
    }

  if (v->flags & DDTT_DLBY)
    {
      if (length < 8)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->downlink_volume = get_u64 (data);
      length -= 8;
    }

  return 0;
}

static int
encode_dropped_dl_traffic_threshold (void *p, u8 ** vec)
{
  pfcp_dropped_dl_traffic_threshold_t *v = p;

  put_u8 (*vec, v->flags);
  if (v->flags & DDTT_DLBY)
    put_u64 (*vec, v->downlink_packets);
  if (v->flags & DDTT_DLPA)
    put_u64 (*vec, v->downlink_packets);

  return 0;
}

#define format_volume_quota format_volume_ie
#define decode_volume_quota decode_volume_ie
#define encode_volume_quota encode_volume_ie

#define format_time_quota format_u32_ie
#define decode_time_quota decode_u32_ie
#define encode_time_quota encode_u32_ie

#define format_start_time format_time_stamp
#define decode_start_time decode_time_stamp_ie
#define encode_start_time encode_time_stamp_ie

#define format_end_time format_time_stamp
#define decode_end_time decode_time_stamp_ie
#define encode_end_time encode_time_stamp_ie

#define format_urr_id format_u32_ie
#define decode_urr_id decode_u32_ie
#define encode_urr_id encode_u32_ie

#define format_linked_urr_id format_u32_ie
#define decode_linked_urr_id decode_u32_ie
#define encode_linked_urr_id encode_u32_ie

static const char *outer_header_creation_description_flags[] = {
  "GTP-U/UDP/IPv4",
  "GTP-U/UDP/IPv6",
  "UDP/IPv4",
  "UDP/IPv6",
  "IPv4",
  "IPv6",
  "C-TAG",
  "S-TAG",
  "N19 Indication",
  "N6 Indication",
  NULL
};

u8 *
format_outer_header_creation (u8 * s, va_list * args)
{
  pfcp_outer_header_creation_t *v =
    va_arg (*args, pfcp_outer_header_creation_t *);

  s = format (s, "%U", format_flags, (u64) v->description,
	      outer_header_creation_description_flags);

  if (v->description & OUTER_HEADER_CREATION_GTP_ANY)
    s = format (s, ",TEID:%08x", v->teid);

  if (v->description &
      (OUTER_HEADER_CREATION_ANY_IP4 | OUTER_HEADER_CREATION_ANY_IP6))
    s = format (s, ",IP:%U", format_ip46_address, &v->ip, IP46_TYPE_ANY);

  if (v->description & OUTER_HEADER_CREATION_UDP_ANY)
    s = format (s, ",Port:%d", v->port);
  if (v->description & OUTER_HEADER_CREATION_C_TAG)
    s = format (s, ",C-Tag:%d", v->c_tag);
  if (v->description & OUTER_HEADER_CREATION_S_TAG)
    s = format (s, ",S-Tag:%d", v->s_tag);

  return s;
}

static int
decode_outer_header_creation (u8 * data, u16 length, void *p)
{
  pfcp_outer_header_creation_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->description = get_u16_little (data);
  length -= 2;

  if (v->description == 0 ||
      (!!(v->description & OUTER_HEADER_CREATION_GTP_ANY)) ==
      (!!(v->description & OUTER_HEADER_CREATION_UDP_ANY)) ||
      (v->description & OUTER_HEADER_CREATION_UDP_ANY) ==
      OUTER_HEADER_CREATION_UDP_ANY)
    {
      pfcp_debug
	("PFCP: invalid bit combination in Outer Header Creation: %04x.",
	 v->description);
      return PFCP_CAUSE_REQUEST_REJECTED;
    }

  if (v->description & OUTER_HEADER_CREATION_GTP_ANY)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->teid = get_u32 (data);
      length -= 4;
    }

  if (v->description & OUTER_HEADER_CREATION_ANY_IP4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4 (v->ip, data);
      length -= 4;
    }

  if (v->description & OUTER_HEADER_CREATION_ANY_IP6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6 (v->ip, data);
      length -= 16;
    }

  if (v->description & OUTER_HEADER_CREATION_UDP_ANY)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->port = get_u16 (data);
    }

  if (v->description & OUTER_HEADER_CREATION_C_TAG)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->c_tag = get_u24 (data);
    }

  if (v->description & OUTER_HEADER_CREATION_S_TAG)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->s_tag = get_u24 (data);
    }

  return 0;
}

static int
encode_outer_header_creation (void *p, u8 ** vec)
{
  pfcp_outer_header_creation_t *v = p;

  put_u16_little (*vec, v->description);

  if (v->description & OUTER_HEADER_CREATION_GTP_ANY)
    put_u32 (*vec, v->teid);

  if (v->description & OUTER_HEADER_CREATION_ANY_IP4)
    put_ip46_ip4 (*vec, v->ip);

  if (v->description & OUTER_HEADER_CREATION_ANY_IP6)
    put_ip46_ip6 (*vec, v->ip);

  if (v->description & OUTER_HEADER_CREATION_UDP_ANY)
    put_u16 (*vec, v->port);

  if (v->description & OUTER_HEADER_CREATION_C_TAG)
    put_u24 (*vec, v->c_tag);

  if (v->description & OUTER_HEADER_CREATION_S_TAG)
    put_u24 (*vec, v->s_tag);

  return 0;
}

#define format_bar_id format_u8_ie
#define decode_bar_id decode_u8_ie
#define encode_bar_id encode_u8_ie

static u8 *
format_cp_function_features (u8 * s, va_list * args)
{
  pfcp_cp_function_features_t *v =
    va_arg (*args, pfcp_cp_function_features_t *);

  return format (s, "LOAD:%d,OVRL:%d,EPFAR:%d,SSET:%d,"
		 "BUNDL:%d,MPAS:%d,ARDR:%d",
		 !!(*v & F_CPFF_LOAD), !!(*v & F_CPFF_OVRL),
		 !!(*v & F_CPFF_EPFAR), !!(*v & F_CPFF_SSET),
		 !!(*v & F_CPFF_BUNDL), !!(*v & F_CPFF_MPAS),
		 !!(*v & F_CPFF_ARDR));
}

#define decode_cp_function_features decode_u8_ie
#define encode_cp_function_features encode_u8_ie

static u8 *
format_usage_information (u8 * s, va_list * args)
{
  pfcp_usage_information_t *v = va_arg (*args, pfcp_usage_information_t *);

  s = format (s, "UBE:%d,UAE:%d,AFT:%d,BEF:%d",
	      !!(*v & USAGE_INFORMATION_BEFORE_QoS_ENFORCEMENT),
	      !!(*v & USAGE_INFORMATION_AFTER_QoS_ENFORCEMENT),
	      !!(*v & USAGE_INFORMATION_AFTER),
	      !!(*v & USAGE_INFORMATION_BEFORE));

  return s;
}

#define decode_usage_information decode_u8_ie
#define encode_usage_information encode_u8_ie

#define format_application_instance_id format_simple_vec_ie
#define decode_application_instance_id decode_simple_vec_ie
#define encode_application_instance_id encode_simple_vec_ie
#define free_application_instance_id free_simple_vec_ie

static const char *flow_direction[] = {
  "Unspecified",
  "Downlink",
  "Uplink",
  "Bidirectional",
  NULL
};

static u8 *
format_flow_information (u8 * s, va_list * args)
{
  pfcp_flow_information_t *v = va_arg (*args, pfcp_flow_information_t *);

  return format (s, "Direction:%U,FD:%v",
		 format_enum, (u64) v->direction, flow_direction,
		 ARRAY_LEN (flow_direction), v->flow_description);
}

static int
decode_flow_information (u8 * data, u16 length, void *p)
{
  pfcp_flow_information_t *v = p;
  u16 len;

  if (length < 3)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->direction = get_u8 (data) & 0x0f;
  len = get_u16 (data);
  length -= 3;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->flow_description, len, data);
  length -= len;

  return 0;
}

static int
encode_flow_information (void *p, u8 ** vec)
{
  pfcp_flow_information_t *v = p;

  put_u8 (*vec, v->direction);
  put_u16 (*vec, vec_len (v->flow_description));
  vec_append (*vec, v->flow_description);

  return 0;
}

static void
free_flow_information (void *p)
{
  pfcp_flow_information_t *v = p;

  vec_free (v->flow_description);
}

static u8 *
format_ue_ip_address (u8 * s, va_list * args)
{
  pfcp_ue_ip_address_t *v = va_arg (*args, pfcp_ue_ip_address_t *);

  s = format (s, "S/D:%d,CHv4:%d,CHv6:%d",
	      !!(v->flags & IE_UE_IP_ADDRESS_SD),
	      !!(v->flags & IE_UE_IP_ADDRESS_CHV4),
	      !!(v->flags & IE_UE_IP_ADDRESS_CHV6));

  if (v->flags & IE_UE_IP_ADDRESS_V4)
    s = format (s, ",IPv4:%U", format_ip4_address, &v->ip4);
  if (v->flags & IE_UE_IP_ADDRESS_V6)
    s = format (s, ",IPv6:%U", format_ip6_address, &v->ip6);

  if (v->flags & IE_UE_IP_ADDRESS_IPv6D)
    s = format (s, ",v6-PD:/%d", v->prefix_delegation_length);
  if (v->flags & IE_UE_IP_ADDRESS_IP6PL)
    s = format (s, ",v6-Prefix:/%d", v->prefix_length);

  return s;
}

static int
decode_ue_ip_address (u8 * data, u16 length, void *p)
{
  pfcp_ue_ip_address_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data);
  length--;

  if (v->flags & IE_UE_IP_ADDRESS_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4 (v->ip4, data);
      length -= 4;
    }

  if (v->flags & IE_UE_IP_ADDRESS_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6 (v->ip6, data);
      length -= 16;
    }

  if (v->flags & IE_UE_IP_ADDRESS_IPv6D)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->prefix_delegation_length = get_u8 (data);
      length--;
    }

  if (v->flags & IE_UE_IP_ADDRESS_IP6PL)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->prefix_length = get_u8 (data);
      length--;
    }
  return 0;
}

static int
encode_ue_ip_address (void *p, u8 ** vec)
{
  pfcp_ue_ip_address_t *v = p;

  put_u8 (*vec, v->flags);
  if (v->flags & IE_UE_IP_ADDRESS_V4)
    put_ip4 (*vec, v->ip4);
  if (v->flags & IE_UE_IP_ADDRESS_V6)
    put_ip6 (*vec, v->ip6);

  if (v->flags & IE_UE_IP_ADDRESS_IPv6D)
    put_u8 (*vec, v->prefix_delegation_length);
  if (v->flags & IE_UE_IP_ADDRESS_IP6PL)
    put_u8 (*vec, v->prefix_length);

  return 0;
}

static u8 *
format_packet_rate_t (u8 * s, va_list * args)
{
  packet_rate_t *v = va_arg (*args, packet_rate_t *);

  switch (v->unit)
    {
    case 1:
      s = format (s, "%u pkts/6min", v->max);
      break;
    case 2:
      s = format (s, "%u pkts/hour", v->max);
      break;
    case 3:
      s = format (s, "%u pkts/day", v->max);
      break;
    case 4:
      s = format (s, "%u pkts/week", v->max);
      break;
    default:
      s = format (s, "%u pkts/min", v->max);
      break;
    }

  return s;
}

static u8 *
format_packet_rate (u8 * s, va_list * args)
{
  pfcp_packet_rate_t *v = va_arg (*args, pfcp_packet_rate_t *);

  s = format (s, "RCSR:%d", !!(v->flags & PACKET_RATE_RCSR));

  if (v->flags & PACKET_RATE_ULPR)
    s = format (s, ",UL:%U", format_packet_rate_t, &v->ul);
  if (v->flags & PACKET_RATE_DLPR)
    s = format (s, ",DL:%U", format_packet_rate_t, &v->dl);
  if (v->flags & PACKET_RATE_APRC)
    {
      if (v->flags & PACKET_RATE_ULPR)
	s = format (s, ",A-UL:%U", format_packet_rate_t, &v->a_ul);
      if (v->flags & PACKET_RATE_DLPR)
	s = format (s, ",A-DL:%U", format_packet_rate_t, &v->a_dl);
    }
  return s;
}

static int
decode_packet_rate (u8 * data, u16 length, void *p)
{
  pfcp_packet_rate_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;
  length--;

  if (v->flags & PACKET_RATE_ULPR)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->ul.unit = get_u8 (data) & 0x0f;
      v->ul.max = get_u16 (data);
      length -= 3;
    }

  if (v->flags & PACKET_RATE_DLPR)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->dl.unit = get_u8 (data) & 0x0f;
      v->dl.max = get_u16 (data);
      length -= 3;
    }

  if (v->flags & PACKET_RATE_APRC)
    {
      if (v->flags & PACKET_RATE_ULPR)
	{
	  if (length < 3)
	    return PFCP_CAUSE_INVALID_LENGTH;

	  v->a_ul.unit = get_u8 (data) & 0x0f;
	  v->a_ul.max = get_u16 (data);
	  length -= 3;
	}

      if (v->flags & PACKET_RATE_DLPR)
	{
	  if (length < 3)
	    return PFCP_CAUSE_INVALID_LENGTH;

	  v->a_dl.unit = get_u8 (data) & 0x0f;
	  v->a_dl.max = get_u16 (data);
	  length -= 3;
	}
    }

  return 0;
}

static int
encode_packet_rate (void *p, u8 ** vec)
{
  pfcp_packet_rate_t *v = p;

  put_u8 (*vec, v->flags);
  if (v->flags & PACKET_RATE_ULPR)
    {
      put_u8 (*vec, v->ul.unit);
      put_u16 (*vec, v->ul.max);
    }
  if (v->flags & PACKET_RATE_DLPR)
    {
      put_u8 (*vec, v->dl.unit);
      put_u16 (*vec, v->dl.max);
    }
  if (v->flags & PACKET_RATE_APRC)
    {
      if (v->flags & PACKET_RATE_ULPR)
	{
	  put_u8 (*vec, v->a_ul.unit);
	  put_u16 (*vec, v->a_ul.max);
	}
      if (v->flags & PACKET_RATE_DLPR)
	{
	  put_u8 (*vec, v->a_dl.unit);
	  put_u16 (*vec, v->a_dl.max);
	}
    }
  return 0;
}

static u8 *
format_outer_header_removal (u8 * s, va_list * args)
{
  pfcp_outer_header_removal_t *v =
    va_arg (*args, pfcp_outer_header_removal_t *);

  return format (s, "%s", *v ? "true" : "false");
}

#define decode_outer_header_removal decode_u8_ie
#define encode_outer_header_removal encode_u8_ie

#define format_recovery_time_stamp format_time_stamp
#define decode_recovery_time_stamp decode_time_stamp_ie
#define encode_recovery_time_stamp encode_time_stamp_ie

static u8 *
format_dl_flow_level_marking (u8 * s, va_list * args)
{
  pfcp_dl_flow_level_marking_t *v =
    va_arg (*args, pfcp_dl_flow_level_marking_t *);

  if (v->flags & DL_FLM_TTC)
    {
      s = format (s, "ToS/TC:0x%04x,", v->tos_traffic_class);
    }

  if (v->flags & DL_FLM_SCI)
    {
      s = format (s, "SCI:0x%04x,", v->service_class_indicator);
    }

  if (v->flags)
    _vec_len (s)--;

  return s;
}

static int
decode_dl_flow_level_marking (u8 * data, u16 length, void *p)
{
  pfcp_dl_flow_level_marking_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;
  length--;

  if (v->flags & DL_FLM_TTC)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->tos_traffic_class = get_u16 (data);
      length -= 2;
    }

  if (v->flags & DL_FLM_SCI)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->service_class_indicator = get_u16 (data);
      length -= 2;
    }
  return 0;
}

static int
encode_dl_flow_level_marking (void *p, u8 ** vec)
{
  pfcp_dl_flow_level_marking_t *v = p;

  put_u8 (*vec, v->flags);

  if (v->flags & DL_FLM_TTC)
    put_u16 (*vec, v->tos_traffic_class);

  if (v->flags & DL_FLM_SCI)
    put_u16 (*vec, v->service_class_indicator);

  return 0;
}

static const char *header_type_enum[] = {
  "HTTP",
  NULL
};

static u8 *
format_header_enrichment (u8 * s, va_list * args)
{
  pfcp_header_enrichment_t *v = va_arg (*args, pfcp_header_enrichment_t *);

  return format (s, "%U,Name:%v,Value:%v",
		 format_enum, (u64) v->type, header_type_enum,
		 ARRAY_LEN (header_type_enum), v->name, v->value);
}

static int
decode_header_enrichment (u8 * data, u16 length, void *p)
{
  pfcp_header_enrichment_t *v = p;
  u16 len;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8 (data) & 0x0f;
  length--;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  len = get_u16 (data);
  length -= 2;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->name, len, data);
  length -= len;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  len = get_u16 (data);
  length -= 2;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->value, len, data);
  length -= len;

  return 0;
}

static int
encode_header_enrichment (void *p, u8 ** vec)
{
  pfcp_header_enrichment_t *v = p;

  put_u8 (*vec, v->type);
  put_u16 (*vec, vec_len (v->name));
  vec_append (*vec, v->name);
  put_u16 (*vec, vec_len (v->value));
  vec_append (*vec, v->value);

  return 0;
}

static u8 *
format_measurement_information (u8 * s, va_list * args)
{
  pfcp_measurement_information_t *v =
    va_arg (*args, pfcp_measurement_information_t *);

  return format (s, "MBQE:%d,INAM:%d,RADI:%d,ISTM:%d,MNOP:%d",
		 !!(v->flags & MEASUREMENT_INFORMATION_MBQE),
		 !!(v->flags & MEASUREMENT_INFORMATION_INAM),
		 !!(v->flags & MEASUREMENT_INFORMATION_RADI),
		 !!(v->flags & MEASUREMENT_INFORMATION_ISTM),
		 !!(v->flags & MEASUREMENT_INFORMATION_MNOP));
}

static int
decode_measurement_information (u8 * data, u16 length, void *p)
{
  pfcp_measurement_information_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & MEASUREMENT_INFORMATION_MASK;

  return 0;
}

static int
encode_measurement_information (void *p, u8 ** vec)
{
  pfcp_measurement_information_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

static u8 *
format_node_report_type (u8 * s, va_list * args)
{
  pfcp_node_report_type_t *v = va_arg (*args, pfcp_node_report_type_t *);

  return format (s, "UPFR:%d,UPRR:%d,GKDR:%d,GPQR",
		 !!(v->flags & NRT_USER_PLANE_PATH_FAILURE_REPORT),
		 !!(v->flags & NRT_USER_PLANE_PATH_RECOVERY_REPORT),
		 !!(v->flags & NRT_CLOCK_DRIFT_REPORT),
		 !!(v->flags & NRT_GTP_U_PATH_QOS_REPORT));
}

static int
decode_node_report_type (u8 * data, u16 length, void *p)
{
  pfcp_node_report_type_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & NRT_MASK;

  return 0;
}

static int
encode_node_report_type (void *p, u8 ** vec)
{
  pfcp_node_report_type_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

static u8 *
format_remote_gtp_u_peer (u8 * s, va_list * args)
{
  pfcp_remote_gtp_u_peer_t *v = va_arg (*args, pfcp_remote_gtp_u_peer_t *);

  s = format (s, "%U", format_ip46_address, &v->ip, IP46_TYPE_ANY);
  if (v->destination_interface < DST_INTF_NUM)
    s =
      format (s, ",DI:%U", format_destination_interface,
	      v->destination_interface);
  if (vec_len (v->network_instance) > 0)
    s = format (s, ",NI: %U", format_network_instance, v->network_instance);

  return s;
}

static int
decode_remote_gtp_u_peer (u8 * data, u16 length, void *p)
{
  pfcp_remote_gtp_u_peer_t *v = p;
  u8 flags;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  flags = get_u8 (data);
  length--;

  if (flags & REMOTE_GTP_U_PEER_IP6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6 (v->ip, data);
      length -= 16;
    }
  else if (flags & REMOTE_GTP_U_PEER_IP4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4 (v->ip, data);
      length -= 4;
    }

  v->destination_interface = ~0;
  if (flags & REMOTE_GTP_U_PEER_DI)
    {
      u16 di_len;

      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      di_len = get_u16 (data);
      length -= 2;

      if (di_len != 1 || length < di_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->destination_interface = get_u8 (data) & 0x0f;
      length -= di_len;

      if (v->destination_interface >= DST_INTF_NUM)
	return PFCP_CAUSE_REQUEST_REJECTED;
    }

  if (flags & REMOTE_GTP_U_PEER_NI)
    {
      u16 ni_len;

      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      ni_len = get_u16 (data);
      length -= 2;

      if (length < ni_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->network_instance, ni_len, data);
      length -= ni_len;
    }

  return 0;
}

static int
encode_remote_gtp_u_peer (void *p, u8 ** vec)
{
  pfcp_remote_gtp_u_peer_t *v = p;
  u8 flags;

  flags = (v->destination_interface != ~0 ? REMOTE_GTP_U_PEER_DI : 0) |
    (vec_len (v->network_instance) > 0 ? REMOTE_GTP_U_PEER_NI : 0);

  if (ip46_address_is_ip4 (&v->ip))
    {
      put_u8 (*vec, flags | REMOTE_GTP_U_PEER_IP4);
      put_ip46_ip4 (*vec, v->ip);
    }
  else
    {
      put_u8 (*vec, flags | REMOTE_GTP_U_PEER_IP6);
      put_ip46_ip6 (*vec, v->ip);
    }

  if (v->destination_interface != ~0)
    {
      put_u16 (*vec, 1);
      put_u8 (*vec, v->destination_interface);
    }

  if (vec_len (v->network_instance) > 0)
    {
      put_u16 (*vec, vec_len (v->network_instance));
      vec_append (*vec, v->network_instance);
    }

  return 0;
}

#define format_ur_seqn format_u32_ie
#define decode_ur_seqn decode_u32_ie
#define encode_ur_seqn encode_u32_ie

#define format_activate_predefined_rules format_simple_vec_ie
#define decode_activate_predefined_rules decode_simple_vec_ie
#define encode_activate_predefined_rules encode_simple_vec_ie
#define free_activate_predefined_rules free_simple_vec_ie

#define format_deactivate_predefined_rules format_simple_vec_ie
#define decode_deactivate_predefined_rules decode_simple_vec_ie
#define encode_deactivate_predefined_rules encode_simple_vec_ie
#define free_deactivate_predefined_rules free_simple_vec_ie

#define format_far_id format_u32_ie
#define decode_far_id decode_u32_ie
#define encode_far_id encode_u32_ie

#define format_qer_id format_u32_ie
#define decode_qer_id decode_u32_ie
#define encode_qer_id encode_u32_ie

static u8 *
format_oci_flags (u8 * s, va_list * args)
{
  pfcp_oci_flags_t *v = va_arg (*args, pfcp_oci_flags_t *);

  return format (s, "AOCI:%d", !!(v->flags & OCI_ASSOCIATE_OCI_WITH_NODE_ID));
}

static int
decode_oci_flags (u8 * data, u16 length, void *p)
{
  pfcp_oci_flags_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x01;

  return 0;
}

static int
encode_oci_flags (void *p, u8 ** vec)
{
  pfcp_oci_flags_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

static u8 *
format_pfcp_association_release_request (u8 * s, va_list * args)
{
  pfcp_pfcp_association_release_request_t *v =
    va_arg (*args, pfcp_pfcp_association_release_request_t *);

  return format (s, "SARR:%d,URSS:%d",
		 !!(v->flags & F_PFCP_ASSOCIATION_RELEASE_REQUEST_SARR),
		 !!(v->flags & F_PFCP_ASSOCIATION_RELEASE_REQUEST_URSS));
}

static int
decode_pfcp_association_release_request (u8 * data, u16 length, void *p)
{
  pfcp_pfcp_association_release_request_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & F_PFCP_ASSOCIATION_RELEASE_REQUEST_MASK;

  return 0;
}

static int
encode_pfcp_association_release_request (void *p, u8 ** vec)
{
  pfcp_pfcp_association_release_request_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

#define format_graceful_release_period format_timer_ie
#define decode_graceful_release_period decode_timer_ie
#define encode_graceful_release_period encode_timer_ie

static char *pdn_type[] = {
  [PDN_TYPE_IPv4] = "IPv4",
  [PDN_TYPE_IPv6] = "IPv6",
  [PDN_TYPE_IPv4v6] = "IPv4v6",
  [PDN_TYPE_NON_IP] = "Non-IP",
  [PDN_TYPE_ETHERNET] = "Ethernet",
};

static u8 *
format_pdn_type (u8 * s, va_list * args)
{
  pfcp_pdn_type_t *v = va_arg (*args, pfcp_pdn_type_t *);

  return format (s, "%U", format_enum, (u64) v->type, pdn_type,
		 ARRAY_LEN (pdn_type));
}

static int
decode_pdn_type (u8 * data, u16 length, void *p)
{
  pfcp_pdn_type_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8 (data) & 0x0f;

  return 0;
}

static int
encode_pdn_type (void *p, u8 ** vec)
{
  pfcp_pdn_type_t *v = p;

  put_u8 (*vec, v->type);

  return 0;
}

static char *failed_rule_type[] = {
  [FAILED_RULE_TYPE_PDR] = "PDR",
  [FAILED_RULE_TYPE_FAR] = "FAR",
  [FAILED_RULE_TYPE_QER] = "QER",
  [FAILED_RULE_TYPE_URR] = "URR",
  [FAILED_RULE_TYPE_BAR] = "BAR",
};

static u8 *
format_failed_rule_id (u8 * s, va_list * args)
{
  pfcp_failed_rule_id_t *n = va_arg (*args, pfcp_failed_rule_id_t *);

  return format (s, "%U: %u",
		 format_enum, (u64) n->type, failed_rule_type,
		 ARRAY_LEN (failed_rule_type), n->id);
}

static int
decode_failed_rule_id (u8 * data, u16 length, void *p)
{
  pfcp_failed_rule_id_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8 (data);
  length--;

  switch (v->type)
    {
    case FAILED_RULE_TYPE_PDR:
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u16 (data);
      break;

    case FAILED_RULE_TYPE_FAR:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u32 (data);
      break;

    case FAILED_RULE_TYPE_QER:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u32 (data);
      break;

    case FAILED_RULE_TYPE_URR:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u32 (data);
      break;

    case FAILED_RULE_TYPE_BAR:
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u8 (data);
      break;

    default:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->id = get_u32 (data);
      break;
    }
  return 0;
}

static int
encode_failed_rule_id (void *p, u8 ** vec)
{
  pfcp_failed_rule_id_t *v = p;

  put_u8 (*vec, v->type);
  switch (v->type)
    {
    case FAILED_RULE_TYPE_PDR:
      put_u16 (*vec, v->id);
      break;

    case FAILED_RULE_TYPE_FAR:
      put_u32 (*vec, v->id);
      break;

    case FAILED_RULE_TYPE_QER:
      put_u32 (*vec, v->id);
      break;

    case FAILED_RULE_TYPE_URR:
      put_u32 (*vec, v->id);
      break;

    case FAILED_RULE_TYPE_BAR:
      put_u8 (*vec, v->id);
      break;

    default:
      put_u32 (*vec, v->id);
      break;
    }
  return 0;
}

static const char *base_time_interval_type[] = {
  "CTP",
  "DTP",
  NULL
};

static u8 *
format_time_quota_mechanism (u8 * s, va_list * args)
{
  pfcp_time_quota_mechanism_t *v =
    va_arg (*args, pfcp_time_quota_mechanism_t *);

  return format (s, "%U,%u",
		 format_enum, (u64) v->base_time_interval_type,
		 base_time_interval_type, ARRAY_LEN (base_time_interval_type),
		 v->base_time_interval);
}

static int
decode_time_quota_mechanism (u8 * data, u16 length, void *p)
{
  pfcp_time_quota_mechanism_t *v = p;

  if (length < 3)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->base_time_interval_type = get_u8 (data) & 0x03;
  v->base_time_interval = get_u32 (data);

  return 0;
}

static int
encode_time_quota_mechanism (void *p, u8 ** vec)
{
  pfcp_time_quota_mechanism_t *v = p;

  put_u8 (*vec, v->base_time_interval_type);
  put_u32 (*vec, v->base_time_interval);

  return 0;
}

u8 *
format_user_plane_ip_resource_information (u8 * s, va_list * args)
{
  pfcp_user_plane_ip_resource_information_t *v =
    va_arg (*args, pfcp_user_plane_ip_resource_information_t *);

  if (v->network_instance)
    s = format (s, "Network Instance: %U, ",
		format_network_instance, v->network_instance);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    s = format (s, "%U, ", format_ip4_address, &v->ip4);
  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    s = format (s, "%U, ", format_ip6_address, &v->ip6);

  if (v->teid_range_indication != 0)
    s =
      format (s, "teid: 0x%02x000000/%u", v->teid_range,
	      v->teid_range_indication);
  else
    _vec_len (s) -= 2;

  return s;
}

static int
decode_user_plane_ip_resource_information (u8 * data, u16 length, void *p)
{
  pfcp_user_plane_ip_resource_information_t *v = p;
  u8 flags;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  flags = get_u8 (data);
  v->flags = flags & USER_PLANE_IP_RESOURCE_INFORMATION_MASK;
  length--;

  v->teid_range_indication = (flags >> 2) & 0x07;
  if (v->teid_range_indication != 0)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->teid_range = get_u8 (data);
      length--;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip4 (v->ip4, data);
      length -= 4;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip6 (v->ip6, data);
      length -= 16;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_ASSONI)
    get_vec (v->network_instance, length, data);

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_ASSOSI)
    v->source_intf = get_u8 (data) & 0x0f;

  return 0;
}

static int
encode_user_plane_ip_resource_information (void *p, u8 ** vec)
{
  pfcp_user_plane_ip_resource_information_t *v = p;
  u8 flags;

  flags = v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_MASK;
  flags |= (v->teid_range_indication & 0x07) << 2;
  flags |=
    v->network_instance ? USER_PLANE_IP_RESOURCE_INFORMATION_ASSONI : 0;

  put_u8 (*vec, flags);

  if (v->teid_range_indication != 0)
    put_u8 (*vec, v->teid_range);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    put_ip4 (*vec, v->ip4);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    put_ip6 (*vec, v->ip6);

  if (v->network_instance)
    vec_append (*vec, v->network_instance);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_ASSOSI)
    put_u8 (*vec, v->source_intf & 0x0f);

  return 0;
}

static void
free_user_plane_ip_resource_information (void *p)
{
  pfcp_user_plane_ip_resource_information_t *v = p;

  vec_free (v->network_instance);
}

#define format_user_plane_inactivity_timer format_u32_ie
#define decode_user_plane_inactivity_timer decode_u32_ie
#define encode_user_plane_inactivity_timer encode_u32_ie

static u8 *
format_multiplier (u8 * s, va_list * args)
{
  pfcp_multiplier_t *v = va_arg (*args, pfcp_multiplier_t *);

  return format (s, "%ldE%d (%f)", v->digits, v->exponent,
		 v->digits * pow (10, v->exponent));
}

static int
decode_multiplier (u8 * data, u16 length, void *p)
{
  pfcp_multiplier_t *v = p;

  if (length < 12)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->digits = (i64) get_u64 (data);
  v->exponent = (i32) get_u32 (data);

  return 0;
}

static int
encode_multiplier (void *p, u8 ** vec)
{
  pfcp_multiplier_t *v = p;

  put_u64 (*vec, (u64) v->digits);
  put_u32 (*vec, (u32) v->exponent);

  return 0;
}

#define format_aggregated_urr_id format_u32_ie
#define decode_aggregated_urr_id decode_u32_ie
#define encode_aggregated_urr_id encode_u32_ie

#define format_subsequent_volume_quota format_volume_ie
#define decode_subsequent_volume_quota decode_volume_ie
#define encode_subsequent_volume_quota encode_volume_ie

#define format_subsequent_time_quota format_u32_ie
#define decode_subsequent_time_quota decode_u32_ie
#define encode_subsequent_time_quota encode_u32_ie

static u8 *
format_rqi (u8 * s, va_list * args)
{
  pfcp_rqi_t *v = va_arg (*args, pfcp_rqi_t *);

  return format (s, "RQI:%d", !!(v->flags & RQI_FLAG));
}

static int
decode_rqi (u8 * data, u16 length, void *p)
{
  pfcp_rqi_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x01;

  return 0;
}

static int
encode_rqi (void *p, u8 ** vec)
{
  pfcp_rqi_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

#define format_qfi format_u8_ie
#define decode_qfi decode_u8_ie
#define encode_qfi encode_u8_ie

#define format_query_urr_reference format_u32_ie
#define decode_query_urr_reference decode_u32_ie
#define encode_query_urr_reference encode_u32_ie

static u8 *
format_additional_usage_reports_information (u8 * s, va_list * args)
{
  pfcp_additional_usage_reports_information_t *v =
    va_arg (*args, pfcp_additional_usage_reports_information_t *);

  if (*v & AURI_FLAG)
    s = format (s, "AURI:true");
  else
    s = format (s, "%u", *v);

  return s;
}

#define decode_additional_usage_reports_information decode_u16_ie
#define encode_additional_usage_reports_information encode_u16_ie

#define format_traffic_endpoint_id format_u8_ie
#define decode_traffic_endpoint_id decode_u8_ie
#define encode_traffic_endpoint_id encode_u8_ie

static u8 *
format_pfcp_mac_address (u8 * s, va_list * args)
{
  pfcp_mac_address_t *v = va_arg (*args, pfcp_mac_address_t *);

  if (v->flags & F_SOURCE_MAC)
    s = format (s, "SRC:%U,", format_mac_address_t, v->src_mac);
  if (v->flags & F_DESTINATION_MAC)
    s = format (s, "DST:%U,", format_mac_address_t, v->dst_mac);
  if (v->flags & F_UPPER_SOURCE_MAC)
    s = format (s, "USRC:%U,", format_mac_address_t, v->upper_src_mac);
  if (v->flags & F_UPPER_DESTINATION_MAC)
    s = format (s, "UDST:%U,", format_mac_address_t, v->upper_dst_mac);

  if (v->flags)
    _vec_len (s)--;

  return s;
}

static int
decode_pfcp_mac_address (u8 * data, u16 length, void *p)
{
  pfcp_mac_address_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data);
  length--;

  if (v->flags & F_SOURCE_MAC)
    {
      if (length < 6)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (&v->src_mac, data, 6);
      data += 6;
      length -= 6;
    }

  if (v->flags & F_DESTINATION_MAC)
    {
      if (length < 6)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (&v->dst_mac, data, 6);
      data += 6;
      length -= 6;
    }

  if (v->flags & F_UPPER_SOURCE_MAC)
    {
      if (length < 6)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (&v->upper_src_mac, data, 6);
      data += 6;
      length -= 6;
    }

  if (v->flags & F_UPPER_DESTINATION_MAC)
    {
      if (length < 6)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (&v->upper_dst_mac, data, 6);
      data += 6;
      length -= 6;
    }

  return 0;
}

static int
encode_pfcp_mac_address (void *p, u8 ** vec)
{
  pfcp_mac_address_t *v = p;

  put_u8 (*vec, v->flags);
  if (v->flags & F_SOURCE_MAC)
    vec_add (*vec, &v->src_mac, 6);
  if (v->flags & F_DESTINATION_MAC)
    vec_add (*vec, &v->dst_mac, 6);
  if (v->flags & F_UPPER_SOURCE_MAC)
    vec_add (*vec, &v->upper_src_mac, 6);
  if (v->flags & F_UPPER_DESTINATION_MAC)
    vec_add (*vec, &v->upper_dst_mac, 6);

  return 0;
}

static u8 *
format_vlan_tag (u8 * s, va_list * args)
{
  pfcp_vlan_tag_t *v = va_arg (*args, pfcp_vlan_tag_t *);

  return format (s, "0x%04x/0x%04", v->tci, v->mask);
}

static int
decode_vlan_tag (u8 * data, u16 length, void *p)
{
  pfcp_vlan_tag_t *v = p;

  if (length < 3)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->mask = clib_host_to_net_u16 (((data[0] & BIT (0)) ? VLAN_MASK_PCP : 0) |
				  ((data[0] & BIT (1)) ? VLAN_MASK_DEI : 0) |
				  ((data[0] & BIT (2)) ? VLAN_MASK_VID : 0));
  v->tci = clib_host_to_net_u16 (((data[1] & 0x07) << 5) |
				 ((data[1] & 0x08) << 1) |
				 ((data[1] & 0xf0) << 4) | data[2]);

  data += 3;
  length -= 3;

  return 0;
}

static int
encode_vlan_tag (void *p, u8 ** vec)
{
  pfcp_vlan_tag_t *v = p;
  u16 mask = clib_net_to_host_u16 (v->mask);
  u16 tci = clib_net_to_host_u16 (v->tci);

  put_u8 (*vec, (((mask & VLAN_MASK_PCP) ? BIT (0) : 0) |
		 ((mask & VLAN_MASK_DEI) ? BIT (1) : 0) |
		 ((mask & VLAN_MASK_VID) ? BIT (2) : 0)));
  put_u16 (*vec, (((tci & VLAN_MASK_PCP) >> 5) |
		  ((tci & VLAN_MASK_DEI) >> 1) |
		  ((tci & 0x0f00) << 4) | (tci & 0x00ff)));
  return 0;
}

#define format_c_tag format_vlan_tag
#define decode_c_tag decode_vlan_tag
#define encode_c_tag encode_vlan_tag

#define format_s_tag format_vlan_tag
#define decode_s_tag decode_vlan_tag
#define encode_s_tag encode_vlan_tag

#define format_ethertype format_u16_ie
#define decode_ethertype decode_u16_ie
#define encode_ethertype encode_u16_ie

static u8 *
format_proxying (u8 * s, va_list * args)
{
  pfcp_proxying_t *v = va_arg (*args, pfcp_proxying_t *);

  return format (s, "ARP:%d,INS:%d",
		 !!(v->flags & F_PROXY_ARP), !!(v->flags & F_PROXY_IP6_NS));
}

static int
decode_proxying (u8 * data, u16 length, void *p)
{
  pfcp_proxying_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;

  return 0;
}

static int
encode_proxying (void *p, u8 ** vec)
{
  pfcp_proxying_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

#define format_ethernet_filter_id format_u32_ie
#define decode_ethernet_filter_id decode_u32_ie
#define encode_ethernet_filter_id encode_u32_ie

static u8 *
format_ethernet_filter_properties (u8 * s, va_list * args)
{
  pfcp_ethernet_filter_properties_t *v =
    va_arg (*args, pfcp_ethernet_filter_properties_t *);

  return format (s, "BIDE:%d",
		 !!(v->flags & F_BIDIRECTIONAL_ETHERNET_FILTER));
}

static int
decode_ethernet_filter_properties (u8 * data, u16 length, void *p)
{
  pfcp_ethernet_filter_properties_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x01;

  return 0;
}

static int
encode_ethernet_filter_properties (void *p, u8 ** vec)
{
  pfcp_ethernet_filter_properties_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

#define format_suggested_buffering_packets_count format_u8_ie
#define decode_suggested_buffering_packets_count decode_u8_ie
#define encode_suggested_buffering_packets_count encode_u8_ie

static u8 *
format_user_id (u8 * s0, va_list * args)
{
  pfcp_user_id_t *v = va_arg (*args, pfcp_user_id_t *);
  u8 *s = s0;

  if (v->imei_len > 0)
    s = format (s0, "IMEI:%U,", format_hex_bytes, v->imei, v->imei_len);
  if (v->imsi_len > 0)
    s = format (s, "IMSI:%U,", format_hex_bytes, v->imsi, v->imsi_len);
  if (v->msisdn_len > 0)
    s = format (s, "MSISDN:%U,", format_hex_bytes, v->msisdn, v->msisdn_len);
  if (vec_len (v->nai) > 0)
    s = format (s, "NAI:%v,", v->nai);

  if (s != s0)
    _vec_len (s)--;

  return s;
}

static int
decode_user_id (u8 * data, u16 length, void *p)
{
  pfcp_user_id_t *v = p;
  u8 flags;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  clib_memset (v, 0, sizeof (*v));

  flags = get_u8 (data);
  length--;

  if (flags & USER_ID_IMEI)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->imei_len = get_u8 (data);
      length--;

      if (v->imei_len > 8 || length < v->imei_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (v->imei, data, v->imei_len);
      data += v->imei_len;
      length -= v->imei_len;
    }

  if (flags & USER_ID_IMSI)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->imsi_len = get_u8 (data);
      length--;

      if (v->imsi_len > 8 || length < v->imsi_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (v->imsi, data, v->imsi_len);
      data += v->imsi_len;
      length -= v->imsi_len;
    }

  if (flags & USER_ID_MSISDN)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->msisdn_len = get_u8 (data);
      length--;

      if (v->msisdn_len > 8 || length < v->msisdn_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      memcpy (v->msisdn, data, v->msisdn_len);
      data += v->msisdn_len;
      length -= v->msisdn_len;
    }

  if (flags & USER_ID_NAI)
    {
      u8 len;

      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      len = get_u8 (data);
      length--;

      if (length < len)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_vec (v->nai, len, data);
      length -= len;
    }

  return 0;
}

static int
encode_user_id (void *p, u8 ** vec)
{
  pfcp_user_id_t *v = p;
  u8 flags;

  flags =
    ((v->imei_len > 0) ? USER_ID_IMEI : 0) |
    ((v->imsi_len > 0) ? USER_ID_IMSI : 0) |
    ((v->msisdn_len > 0) ? USER_ID_MSISDN : 0) |
    ((vec_len (v->nai) > 0) ? USER_ID_NAI : 0);

  put_u8 (*vec, flags);

  if (v->imei_len > 0)
    {
      put_u8 (*vec, v->imei_len);
      vec_add (*vec, v->imei, v->imei_len);
    }

  if (v->imsi_len > 0)
    {
      put_u8 (*vec, v->imsi_len);
      vec_add (*vec, v->imsi, v->imsi_len);
    }

  if (v->msisdn_len > 0)
    {
      put_u8 (*vec, v->msisdn_len);
      vec_add (*vec, v->msisdn, v->msisdn_len);
    }

  if (vec_len (v->nai) > 0)
    {
      put_u8 (*vec, vec_len (v->nai));
      vec_append (*vec, v->nai);
    }

  return 0;
}

static void
free_user_id (void *p)
{
  pfcp_user_id_t *v = p;

  vec_free (v->nai);
}

static u8 *
format_ethernet_pdu_session_information (u8 * s, va_list * args)
{
  pfcp_ethernet_pdu_session_information_t *v =
    va_arg (*args, pfcp_ethernet_pdu_session_information_t *);

  return format (s, "ETHI:%d", !!(v->flags & F_ETHERNET_INDICATION));
}

static int
decode_ethernet_pdu_session_information (u8 * data, u16 length, void *p)
{
  pfcp_ethernet_pdu_session_information_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x01;

  return 0;
}

static int
encode_ethernet_pdu_session_information (void *p, u8 ** vec)
{
  pfcp_ethernet_pdu_session_information_t *v = p;

  put_u8 (*vec, v->flags);

  return 0;
}

static u8 *
format_mac_addresses_vec (u8 * s, va_list * args)
{
  pfcp_mac_addresses_vec_t *v = va_arg (*args, pfcp_mac_addresses_vec_t *);
  mac_address_t *mac;

  s = format (s, "[");
  vec_foreach (mac, *v)
  {
    s = format (s, "%U,", format_mac_address_t, mac);
  }
  if (vec_len (*v) != 0)
    _vec_len (s)--;
  s = format (s, "]");

  return s;
}

static int
decode_mac_addresses_vec (u8 * data, u16 length, void *p)
{
  pfcp_mac_addresses_vec_t *v = p;
  u8 cnt;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  cnt = get_u8 (data);
  if (length < cnt * 6)
    return PFCP_CAUSE_INVALID_LENGTH;

  vec_add (*v, data, cnt);
  data += cnt * 6;
  length -= cnt * 6;

  return 0;
}

static int
encode_mac_addresses_vec (void *p, u8 ** vec)
{
  pfcp_mac_addresses_vec_t *v = p;
  mac_address_t *mac;

  put_u8 (*vec, vec_len (*v));

  vec_foreach (mac, *v)
  {
    vec_add (*vec, mac, 1);
  }

  return 0;
}

static void
free_mac_addresses_vec (void *p)
{
  pfcp_mac_addresses_vec_t *v = p;

  vec_free (*v);
}

#define format_mac_addresses_detected format_mac_addresses_vec
#define decode_mac_addresses_detected decode_mac_addresses_vec
#define encode_mac_addresses_detected encode_mac_addresses_vec
#define free_mac_addresses_detected free_mac_addresses_vec

#define format_mac_addresses_removed format_mac_addresses_vec
#define decode_mac_addresses_removed decode_mac_addresses_vec
#define encode_mac_addresses_removed encode_mac_addresses_vec
#define free_mac_addresses_removed free_mac_addresses_vec

#define format_ethernet_inactivity_timer format_u32_ie
#define decode_ethernet_inactivity_timer decode_u32_ie
#define encode_ethernet_inactivity_timer encode_u32_ie

#define format_event_quota format_u32_ie
#define decode_event_quota decode_u32_ie
#define encode_event_quota encode_u32_ie

#define format_event_threshold format_u32_ie
#define decode_event_threshold decode_u32_ie
#define encode_event_threshold encode_u32_ie

#define format_subsequent_event_quota format_u32_ie
#define decode_subsequent_event_quota decode_u32_ie
#define encode_subsequent_event_quota encode_u32_ie

#define format_subsequent_event_threshold format_u32_ie
#define decode_subsequent_event_threshold decode_u32_ie
#define encode_subsequent_event_threshold encode_u32_ie

static u8 *
format_digit (u8 * s, u8 c)
{
  switch (c)
    {
    case 0 ... 9:
      vec_add1 (s, c + '0');
      break;
    default:
      break;
    }
  return s;
}

static u8 *
format_mccmcn (u8 * s, va_list * args)
{
  u8 *v = va_arg (*args, u8 *);

  s = format_digit (s, v[0] & 0x0f);
  s = format_digit (s, v[0] >> 4);
  s = format_digit (s, v[1] & 0x0f);
  vec_add1 (s, ':');
  s = format_digit (s, v[2] & 0x0f);
  s = format_digit (s, v[2] >> 4);
  s = format_digit (s, v[1] >> 4);

  return s;
}

static u8 *
format_trace_information (u8 * s, va_list * args)
{
  pfcp_trace_information_t *v = va_arg (*args, pfcp_trace_information_t *);
  u8 *i;

  s =
    format (s, "MCC/MNC:%U,Id:0x%08x,Evs:", format_mccmcn, &v->mccmnc[0],
	    v->trace_id);
  vec_foreach (i, v->triggering_events) s = format (s, "%02x", *i);
  s = format (s, ",Depth: %u,If:", v->trace_depth);
  vec_foreach (i, v->interfaces) s = format (s, "%02x", *i);
  s = format (s, ",IP: %U",
	      format_ip46_address, &v->collection_entity, IP46_TYPE_ANY);

  return s;
}

static int
decode_trace_information (u8 * data, u16 length, void *p)
{
  pfcp_trace_information_t *v = p;
  u8 len;

  if (length < 8)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->mccmnc[0] = get_u8 (data);
  v->mccmnc[1] = get_u8 (data);
  v->mccmnc[2] = get_u8 (data);

  v->trace_id = get_u32 (data);

  len = get_u8 (data);
  length -= 8;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->triggering_events, len, data);
  length -= len;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  len = get_u8 (data);
  length--;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  get_vec (v->interfaces, len, data);
  length -= len;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  len = get_u8 (data);
  length--;

  if (length < len)
    return PFCP_CAUSE_INVALID_LENGTH;

  switch (len)
    {
    case 4:
      get_ip46_ip4 (v->collection_entity, data);

    case 16:
      get_ip46_ip6 (v->collection_entity, data);
      break;

    default:
      return PFCP_CAUSE_INVALID_LENGTH;
    }
  length -= len;

  return 0;
}

static int
encode_trace_information (void *p, u8 ** vec)
{
  pfcp_trace_information_t *v = p;

  put_u8 (*vec, v->mccmnc[0]);
  put_u8 (*vec, v->mccmnc[1]);
  put_u8 (*vec, v->mccmnc[2]);
  put_u32 (*vec, v->trace_id);

  put_u8 (*vec, vec_len (v->triggering_events));
  vec_append (*vec, v->triggering_events);

  put_u8 (*vec, v->trace_depth);

  put_u8 (*vec, vec_len (v->interfaces));
  vec_append (*vec, v->interfaces);

  if (ip46_address_is_ip4 (&v->collection_entity))
    {
      put_u8 (*vec, 4);
      put_ip46_ip4 (*vec, v->collection_entity);
    }
  else
    {
      put_u8 (*vec, 16);
      put_ip46_ip6 (*vec, v->collection_entity);
    }

  return 0;
}

static void
free_trace_information (void *p)
{
  pfcp_trace_information_t *v = p;

  vec_free (v->triggering_events);
  vec_free (v->interfaces);
}

#define format_framed_route format_simple_vec_ie
#define decode_framed_route decode_simple_vec_ie
#define encode_framed_route encode_simple_vec_ie

#define format_framed_routing format_u8_ie
#define decode_framed_routing decode_u8_ie
#define encode_framed_routing encode_u8_ie

#define format_framed_ipv6_route format_simple_vec_ie
#define decode_framed_ipv6_route decode_simple_vec_ie
#define encode_framed_ipv6_route encode_simple_vec_ie

#define format_event_time_stamp format_time_stamp
#define decode_event_time_stamp decode_time_stamp_ie
#define encode_event_time_stamp encode_time_stamp_ie

#define format_averaging_window format_u32_ie
#define decode_averaging_window decode_u32_ie
#define encode_averaging_window encode_u32_ie

#define format_paging_policy_indicator format_u8_ie
#define decode_paging_policy_indicator decode_u8_ie
#define encode_paging_policy_indicator encode_u8_ie

#define format_apn_dnn format_simple_vec_ie
#define decode_apn_dnn decode_simple_vec_ie
#define encode_apn_dnn encode_simple_vec_ie

static char *tgpp_interface_type[] = {
  [0] = "S1-U",
  [1] = "S5/S8-U",
  [2] = "S4-U",
  [3] = "S11-U",
  [4] = "S12-U",
  [5] = "Gn/Gp-U",
  [6] = "S2a-U",
  [7] = "S2b-U",
  [8] = "eNodeB GTP-U interface for DL data forwarding",
  [9] = "eNodeB GTP-U interface for UL data forwarding",
  [10] = "SGW/UPF GTP-U interface for DL data forwarding",
  [11] = "N3 3GPP Access",
  [12] = "N3 Trusted Non-3GPP Access",
  [13] = "N3 Untrusted Non-3GPP Access",
  [14] = "N3 for data forwarding",
  [15] = "N9",
  [16] = "SGi",
  [17] = "N6",
  [18] = "N19"
};

static u8 *
format_tgpp_interface_type (u8 * s, va_list * args)
{
  pfcp_tgpp_interface_type_t *v =
    va_arg (*args, pfcp_tgpp_interface_type_t *);

  return format (s, "%U", format_enum, (u64) * v, tgpp_interface_type,
		 ARRAY_LEN (tgpp_interface_type));
}

#define decode_tgpp_interface_type decode_u8_ie
#define encode_tgpp_interface_type encode_u8_ie

static u8 *
format_pfcpsrreq_flags (u8 * s, va_list * args)
{
  pfcp_pfcpsrreq_flags_t *v = va_arg (*args, pfcp_pfcpsrreq_flags_t *);

  return format (s, "PSDBU:%d", !!(*v & PFCPSRREQ_PSDBU));
}

#define decode_pfcpsrreq_flags decode_u8_ie
#define encode_pfcpsrreq_flags encode_u8_ie

static u8 *
format_pfcpaureq_flags (u8 * s, va_list * args)
{
  pfcp_pfcpaureq_flags_t *v = va_arg (*args, pfcp_pfcpaureq_flags_t *);

  return format (s, "PARPS:%d", !!(*v & PFCPAUREQ_PARPS));
}

#define decode_pfcpaureq_flags decode_u8_ie
#define encode_pfcpaureq_flags encode_u8_ie

#define format_activation_time format_time_stamp
#define decode_activation_time decode_time_stamp_ie
#define encode_activation_time encode_time_stamp_ie

#define format_deactivation_time format_time_stamp
#define decode_deactivation_time decode_time_stamp_ie
#define encode_deactivation_time encode_time_stamp_ie

#define format_mar_id format_u16_ie
#define decode_mar_id decode_u16_ie
#define encode_mar_id encode_u16_ie

static char *steering_functionality[] = {
  [STEERING_FUNCTIONALITY_ATSSS_LL] = "ATSSS-LL",
  [STEERING_FUNCTIONALITY_MPTCP] = "MPTCP",
};

static u8 *
format_steering_functionality (u8 * s, va_list * args)
{
  pfcp_steering_functionality_t *v =
    va_arg (*args, pfcp_steering_functionality_t *);

  return format (s, "%U", format_enum, (u64) * v, steering_functionality,
		 ARRAY_LEN (steering_functionality));
}

#define decode_steering_functionality decode_u8_ie
#define encode_steering_functionality encode_u8_ie

static char *steering_mode[] = {
  [STEERING_MODE_ACTIVE_STANDBY] = "Active-Standby",
  [STEERING_MODE_SMALLEST_DELAY] = "Smallest Delay",
  [STEERING_MODE_LOAD_BALANCING] = "Load Balancing",
  [STEERING_MODE_PRIORITY_BASED] = "Priority-based",
};

static u8 *
format_steering_mode (u8 * s, va_list * args)
{
  pfcp_steering_mode_t *v = va_arg (*args, pfcp_steering_mode_t *);

  return format (s, "%U", format_enum, (u64) * v, steering_mode,
		 ARRAY_LEN (steering_mode));
}

#define decode_steering_mode decode_u8_ie
#define encode_steering_mode encode_u8_ie

#define format_weight format_u8_ie
#define decode_weight decode_u8_ie
#define encode_weight encode_u8_ie

static char *priority[] = {
  [PRIORITY_ACTIVE] = "Active",
  [PRIORITY_STANDBY] = "Standby",
  [PRIORITY_HIGH] = "High",
  [PRIORITY_LOW] = "Low",
};

static u8 *
format_priority (u8 * s, va_list * args)
{
  pfcp_priority_t *v = va_arg (*args, pfcp_priority_t *);

  return format (s, "%U", format_enum, (u64) * v, priority,
		 ARRAY_LEN (priority));
}

#define decode_priority decode_u8_ie
#define encode_priority encode_u8_ie

#define format_ue_ip_address_pool_identity format_simple_vec_ie
#define decode_ue_ip_address_pool_identity decode_simple_vec_ie
#define encode_ue_ip_address_pool_identity encode_simple_vec_ie

static u8 *
format_alternative_smf_ip_address (u8 * s, va_list * args)
{
  pfcp_alternative_smf_ip_address_t *n =
    va_arg (*args, pfcp_alternative_smf_ip_address_t *);

  switch (n->flags & (ALTERNATIVE_SMF_IP_ADDRESS_V4 |
		      ALTERNATIVE_SMF_IP_ADDRESS_V6))
    {
    case ALTERNATIVE_SMF_IP_ADDRESS_V4:
      s = format (s, "%U", format_ip4_address, &n->ip4);
      break;

    case ALTERNATIVE_SMF_IP_ADDRESS_V6:
      s = format (s, "%U", format_ip6_address, &n->ip6);
      break;

    case (ALTERNATIVE_SMF_IP_ADDRESS_V4 | ALTERNATIVE_SMF_IP_ADDRESS_V6):
      s =
	format (s, "%U,%U", format_ip4_address, &n->ip4, format_ip6_address,
		&n->ip6);
      break;
    }

  return s;
}

static int
decode_alternative_smf_ip_address (u8 * data, u16 length, void *p)
{
  pfcp_alternative_smf_ip_address_t *v = p;

  if (length < 9)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8 (data) & 0x03;
  if (v->flags == 0)
    {
      pfcp_debug
	("PFCP: Alternative SMF IP Address with unsupported flags: %02x.",
	 v->flags);
      return -1;
    }

  if (v->flags & ALTERNATIVE_SMF_IP_ADDRESS_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4 (v->ip4, data);
      length -= 4;
    }

  if (v->flags & ALTERNATIVE_SMF_IP_ADDRESS_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6 (v->ip6, data);
    }

  return 0;
}

static int
encode_alternative_smf_ip_address (void *p, u8 ** vec)
{
  pfcp_alternative_smf_ip_address_t *v = p;

  put_u8 (*vec, v->flags);

  if (v->flags & ALTERNATIVE_SMF_IP_ADDRESS_V4)
    put_ip4 (*vec, v->ip4);

  if (v->flags & ALTERNATIVE_SMF_IP_ADDRESS_V6)
    put_ip6 (*vec, v->ip6);

  return 0;
}

#define format_tp_packet_measurement format_volume_ie
#define decode_tp_packet_measurement decode_volume_ie
#define encode_tp_packet_measurement encode_volume_ie

#define format_tp_build_id format_simple_vec_ie
#define decode_tp_build_id decode_simple_vec_ie
#define encode_tp_build_id encode_simple_vec_ie
#define free_tp_build_id free_simple_vec_ie

#define format_tp_now format_sntp_time_stamp
#define decode_tp_now decode_sntp_time_stamp_ie
#define encode_tp_now encode_sntp_time_stamp_ie

#define format_tp_start_time format_sntp_time_stamp
#define decode_tp_start_time decode_sntp_time_stamp_ie
#define encode_tp_start_time encode_sntp_time_stamp_ie

#define format_tp_end_time format_sntp_time_stamp
#define decode_tp_end_time decode_sntp_time_stamp_ie
#define encode_tp_end_time encode_sntp_time_stamp_ie

/* Grouped Information Elements */


/**********************************************************/

/* *INDENT-OFF* */
static struct pfcp_group_ie_def pfcp_create_pdr_group[] =
  {
    [CREATE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_create_pdr_t, pdr_id)
    },
    [CREATE_PDR_PRECEDENCE] = {
      .type = PFCP_IE_PRECEDENCE,
      .offset = offsetof(pfcp_create_pdr_t, precedence)
    },
    [CREATE_PDR_PDI] = {
      .type = PFCP_IE_PDI,
      .offset = offsetof(pfcp_create_pdr_t, pdi)
    },
    [CREATE_PDR_OUTER_HEADER_REMOVAL] = {
      .type = PFCP_IE_OUTER_HEADER_REMOVAL,
      .offset = offsetof(pfcp_create_pdr_t, outer_header_removal)
    },
    [CREATE_PDR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_create_pdr_t, far_id)
    },
    [CREATE_PDR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_create_pdr_t, urr_id)
    },
    [CREATE_PDR_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .is_array = true,
      .offset = offsetof(pfcp_create_pdr_t, qer_id)
    },
    [CREATE_PDR_ACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_ACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_create_pdr_t, activate_predefined_rules)
    },
    [CREATE_PDR_ACTIVATION_TIME] = {
      .type = PFCP_IE_ACTIVATION_TIME,
      .offset = offsetof(pfcp_create_pdr_t, activation_time)
    },
    [CREATE_PDR_DEACTIVATION_TIME] = {
      .type = PFCP_IE_DEACTIVATION_TIME,
      .offset = offsetof(pfcp_create_pdr_t, deactivation_time)
    },
    [CREATE_PDR_MAR_ID] = {
      .type = PFCP_IE_MAR_ID,
      .offset = offsetof(pfcp_create_pdr_t, mar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_pdi_group[] =
  {
    [PDI_SOURCE_INTERFACE] = {
      .type = PFCP_IE_SOURCE_INTERFACE,
      .offset = offsetof(pfcp_pdi_t, source_interface)
    },
    [PDI_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_pdi_t, f_teid)
    },
    [PDI_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_pdi_t, network_instance)
    },
    [PDI_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_pdi_t, ue_ip_address)
    },
    [PDI_SDF_FILTER] = {
      .type = PFCP_IE_SDF_FILTER,
      .is_array = true,
      .offset = offsetof(pfcp_pdi_t, sdf_filter)
    },
    [PDI_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_pdi_t, application_id)
    },
    [PDI_ETHERNET_PDU_SESSION_INFORMATION] = {
      .type = PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION,
      .offset = offsetof(pfcp_pdi_t, ethernet_pdu_session_information)
    },
    [PDI_ETHERNET_PACKET_FILTER] = {
      .type = PFCP_IE_ETHERNET_PACKET_FILTER,
      .offset = offsetof(pfcp_pdi_t, ethernet_packet_filter)
    },
    [PDI_QFI] = {
      .type = PFCP_IE_QFI,
      .offset = offsetof(pfcp_pdi_t, qfi)
    },
    [PDI_FRAMED_ROUTE] = {
      .type = PFCP_IE_FRAMED_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_pdi_t, framed_route)
    },
    [PDI_FRAMED_ROUTING] = {
      .type = PFCP_IE_FRAMED_ROUTING,
      .offset = offsetof(pfcp_pdi_t, framed_routing)
    },
    [PDI_FRAMED_IPV6_ROUTE] = {
      .type = PFCP_IE_FRAMED_IPV6_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_pdi_t, framed_ipv6_route)
    },
    [PDI_SOURCE_INTERFACE_TYPE] = {
      .type = PFCP_IE_TGPP_INTERFACE_TYPE,
      .offset = offsetof(pfcp_pdi_t, source_interface_type)
    },
  };

static struct pfcp_group_ie_def pfcp_create_far_group[] =
  {
    [CREATE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_create_far_t, far_id)
    },
    [CREATE_FAR_APPLY_ACTION] = {
      .type = PFCP_IE_APPLY_ACTION,
      .offset = offsetof(pfcp_create_far_t, apply_action)
    },
    [CREATE_FAR_FORWARDING_PARAMETERS] = {
      .type = PFCP_IE_FORWARDING_PARAMETERS,
      .offset = offsetof(pfcp_create_far_t, forwarding_parameters)
    },
    [CREATE_FAR_DUPLICATING_PARAMETERS] = {
      .type = PFCP_IE_DUPLICATING_PARAMETERS,
      .offset = offsetof(pfcp_create_far_t, duplicating_parameters)
    },
    [CREATE_FAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_create_far_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_forwarding_parameters_group[] =
  {
    [FORWARDING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_forwarding_parameters_t, destination_interface)
    },
    [FORWARDING_PARAMETERS_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_forwarding_parameters_t, network_instance)
    },
    [FORWARDING_PARAMETERS_REDIRECT_INFORMATION] = {
      .type = PFCP_IE_REDIRECT_INFORMATION,
      .offset = offsetof(pfcp_forwarding_parameters_t, redirect_information)
    },
    [FORWARDING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_forwarding_parameters_t, outer_header_creation)
    },
    [FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_forwarding_parameters_t, transport_level_marking)
    },
    [FORWARDING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_forwarding_parameters_t, forwarding_policy)
    },
    [FORWARDING_PARAMETERS_HEADER_ENRICHMENT] = {
      .type = PFCP_IE_HEADER_ENRICHMENT,
      .offset = offsetof(pfcp_forwarding_parameters_t, header_enrichment)
    },
    [FORWARDING_PARAMETERS_LINKED_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_forwarding_parameters_t, linked_traffic_endpoint_id)
    },
    [FORWARDING_PARAMETERS_PROXYING] = {
      .type = PFCP_IE_PROXYING,
      .offset = offsetof(pfcp_forwarding_parameters_t, proxying)
    },
    [FORWARDING_PARAMETERS_DESTINATION_INTERFACE_TYPE] = {
      .type = PFCP_IE_TGPP_INTERFACE_TYPE,
      .offset = offsetof(pfcp_forwarding_parameters_t, destination_interface_type)
    },
  };

static struct pfcp_group_ie_def pfcp_duplicating_parameters_group[] =
  {
    [DUPLICATING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_duplicating_parameters_t, destination_interface)
    },
    [DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_duplicating_parameters_t, outer_header_creation)
    },
    [DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_duplicating_parameters_t, transport_level_marking)
    },
    [DUPLICATING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_duplicating_parameters_t, forwarding_policy)
    },
  };

static struct pfcp_group_ie_def pfcp_create_urr_group[] =
  {
    [CREATE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_create_urr_t, urr_id)
    },
    [CREATE_URR_MEASUREMENT_METHOD] = {
      .type = PFCP_IE_MEASUREMENT_METHOD,
      .offset = offsetof(pfcp_create_urr_t, measurement_method)
    },
    [CREATE_URR_REPORTING_TRIGGERS] = {
      .type = PFCP_IE_REPORTING_TRIGGERS,
      .offset = offsetof(pfcp_create_urr_t, reporting_triggers)
    },
    [CREATE_URR_MEASUREMENT_PERIOD] = {
      .type = PFCP_IE_MEASUREMENT_PERIOD,
      .offset = offsetof(pfcp_create_urr_t, measurement_period)
    },
    [CREATE_URR_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, volume_threshold)
    },
    [CREATE_URR_VOLUME_QUOTA] = {
      .type = PFCP_IE_VOLUME_QUOTA,
      .offset = offsetof(pfcp_create_urr_t, volume_quota)
    },
    [CREATE_URR_TIME_THRESHOLD] = {
      .type = PFCP_IE_TIME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, time_threshold)
    },
    [CREATE_URR_TIME_QUOTA] = {
      .type = PFCP_IE_TIME_QUOTA,
      .offset = offsetof(pfcp_create_urr_t, time_quota)
    },
    [CREATE_URR_QUOTA_HOLDING_TIME] = {
      .type = PFCP_IE_QUOTA_HOLDING_TIME,
      .offset = offsetof(pfcp_create_urr_t, quota_holding_time)
    },
    [CREATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD] = {
      .type = PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, dropped_dl_traffic_threshold)
    },
    [CREATE_URR_MONITORING_TIME] = {
      .type = PFCP_IE_MONITORING_TIME,
      .offset = offsetof(pfcp_create_urr_t, monitoring_time)
    },
    [CREATE_URR_SUBSEQUENT_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, subsequent_volume_threshold)
    },
    [CREATE_URR_SUBSEQUENT_TIME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, subsequent_time_threshold)
    },
    [CREATE_URR_INACTIVITY_DETECTION_TIME] = {
      .type = PFCP_IE_INACTIVITY_DETECTION_TIME,
      .offset = offsetof(pfcp_create_urr_t, inactivity_detection_time)
    },
    [CREATE_URR_LINKED_URR_ID] = {
      .type = PFCP_IE_LINKED_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_create_urr_t, linked_urr_id)
    },
    [CREATE_URR_MEASUREMENT_INFORMATION] = {
      .type = PFCP_IE_MEASUREMENT_INFORMATION,
      .offset = offsetof(pfcp_create_urr_t, measurement_information)
    },
    [CREATE_URR_TIME_QUOTA_MECHANISM] = {
      .type = PFCP_IE_TIME_QUOTA_MECHANISM,
      .offset = offsetof(pfcp_create_urr_t, time_quota_mechanism)
    },
    [CREATE_URR_AGGREGATED_URRS] = {
      .type = PFCP_IE_AGGREGATED_URRS,
      .offset = offsetof(pfcp_create_urr_t, aggregated_urrs)
    },
    [CREATE_URR_FAR_ID_FOR_QUOTE_ACTION] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_create_urr_t, far_id_for_quota_action)
    },
    [CREATE_URR_ETHERNET_INACTIVITY_TIMER] = {
      .type = PFCP_IE_ETHERNET_INACTIVITY_TIMER,
      .offset = offsetof(pfcp_create_urr_t, ethernet_inactivity_timer)
    },
    [CREATE_URR_ADDITIONAL_MONITORING_TIME] = {
      .type = PFCP_IE_ADDITIONAL_MONITORING_TIME,
      .is_array = true,
     .offset = offsetof(pfcp_create_urr_t, additional_monitoring_time)
    },
  };

static struct pfcp_group_ie_def pfcp_create_qer_group[] =
  {
    [CREATE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_create_qer_t, qer_id)
    },
    [CREATE_QER_QER_CORRELATION_ID] = {
      .type = PFCP_IE_QER_CORRELATION_ID,
      .offset = offsetof(pfcp_create_qer_t, qer_correlation_id)
    },
    [CREATE_QER_GATE_STATUS] = {
      .type = PFCP_IE_GATE_STATUS,
      .offset = offsetof(pfcp_create_qer_t, gate_status)
    },
    [CREATE_QER_MBR] = {
      .type = PFCP_IE_MBR,
      .offset = offsetof(pfcp_create_qer_t, mbr)
    },
    [CREATE_QER_GBR] = {
      .type = PFCP_IE_GBR,
      .offset = offsetof(pfcp_create_qer_t, gbr)
    },
    [CREATE_QER_PACKET_RATE] = {
      .type = PFCP_IE_PACKET_RATE,
      .offset = offsetof(pfcp_create_qer_t, packet_rate)
    },
    [CREATE_QER_DL_FLOW_LEVEL_MARKING] = {
      .type = PFCP_IE_DL_FLOW_LEVEL_MARKING,
      .offset = offsetof(pfcp_create_qer_t, dl_flow_level_marking)
    },
    [CREATE_QER_QOS_FLOW_IDENTIFIER] = {
      .type = PFCP_IE_QFI,
      .offset = offsetof(pfcp_create_qer_t, qos_flow_identifier)
    },
    [CREATE_QER_REFLECTIVE_QOS] = {
      .type = PFCP_IE_RQI,
      .offset = offsetof(pfcp_create_qer_t, reflective_qos)
    },
    [CREATE_QER_PAGING_POLICY_INDICATOR] = {
      .type = PFCP_IE_PAGING_POLICY_INDICATOR,
      .offset = offsetof(pfcp_create_qer_t, paging_policy_indicator)
    },
    [CREATE_QER_AVERAGING_WINDOW] = {
      .type = PFCP_IE_AVERAGING_WINDOW,
      .offset = offsetof(pfcp_create_qer_t, averaging_window)
    },
  };

static struct pfcp_group_ie_def pfcp_created_pdr_group[] =
  {
    [CREATED_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_created_pdr_t, pdr_id)
    },
    [CREATED_PDR_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_created_pdr_t, f_teid)
    },
    [CREATED_PDR_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_created_pdr_t, ue_ip_address)
    },
  };

static struct pfcp_group_ie_def pfcp_update_pdr_group[] =
  {
    [UPDATE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_update_pdr_t, pdr_id)
    },
    [UPDATE_PDR_OUTER_HEADER_REMOVAL] = {
      .type = PFCP_IE_OUTER_HEADER_REMOVAL,
      .offset = offsetof(pfcp_update_pdr_t, outer_header_removal)
    },
    [UPDATE_PDR_PRECEDENCE] = {
      .type = PFCP_IE_PRECEDENCE,
      .offset = offsetof(pfcp_update_pdr_t, precedence)
    },
    [UPDATE_PDR_PDI] = {
      .type = PFCP_IE_PDI,
      .offset = offsetof(pfcp_update_pdr_t, pdi)
    },
    [UPDATE_PDR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_pdr_t, far_id)
    },
    [UPDATE_PDR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_update_pdr_t, urr_id)
    },
    [UPDATE_PDR_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .is_array = true,
      .offset = offsetof(pfcp_update_pdr_t, qer_id)
    },
    [UPDATE_PDR_ACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_ACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_update_pdr_t, activate_predefined_rules)
    },
    [UPDATE_PDR_DEACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_DEACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_update_pdr_t, deactivate_predefined_rules)
    },
    [UPDATE_PDR_ACTIVATION_TIME] = {
      .type = PFCP_IE_ACTIVATION_TIME,
      .offset = offsetof(pfcp_update_pdr_t, activation_time)
    },
    [UPDATE_PDR_DEACTIVATION_TIME] = {
      .type = PFCP_IE_DEACTIVATION_TIME,
      .offset = offsetof(pfcp_update_pdr_t, deactivation_time)
    },
  };

static struct pfcp_group_ie_def pfcp_update_far_group[] =
  {
    [UPDATE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_far_t, far_id)
    },
    [UPDATE_FAR_APPLY_ACTION] = {
      .type = PFCP_IE_APPLY_ACTION,
      .offset = offsetof(pfcp_update_far_t, apply_action)
    },
    [UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS] = {
      .type = PFCP_IE_UPDATE_FORWARDING_PARAMETERS,
      .offset = offsetof(pfcp_update_far_t, update_forwarding_parameters)
    },
    [UPDATE_FAR_UPDATE_DUPLICATING_PARAMETERS] = {
      .type = PFCP_IE_UPDATE_DUPLICATING_PARAMETERS,
      .offset = offsetof(pfcp_update_far_t, update_duplicating_parameters)
    },
    [UPDATE_FAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_far_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_update_forwarding_parameters_group[] =
  {
    [UPDATE_FORWARDING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, destination_interface)
    },
    [UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, network_instance)
    },
    [UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION] = {
      .type = PFCP_IE_REDIRECT_INFORMATION,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, redirect_information)
    },
    [UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, outer_header_creation)
    },
    [UPDATE_FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, transport_level_marking)
    },
    [UPDATE_FORWARDING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, forwarding_policy)
    },
    [UPDATE_FORWARDING_PARAMETERS_HEADER_ENRICHMENT] = {
      .type = PFCP_IE_HEADER_ENRICHMENT,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, header_enrichment)
    },
    [UPDATE_FORWARDING_PARAMETERS_PFCPSMREQ_FLAGS] = {
      .type = PFCP_IE_PFCPSMREQ_FLAGS,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, pfcpsmreq_flags)
    },
    [UPDATE_FORWARDING_PARAMETERS_LINKED_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, linked_traffic_endpoint_id)
    },
    [UPDATE_FORWARDING_PARAMETERS_DESTINATION_INTERFACE_TYPE] = {
      .type = PFCP_IE_TGPP_INTERFACE_TYPE,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, destination_interface_type)
    },
  };

static struct pfcp_group_ie_def pfcp_update_bar_response_group[] =
  {
    [UPDATE_BAR_RESPONSE_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_bar_response_t, bar_id)
    },
    [UPDATE_BAR_RESPONSE_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_update_bar_response_t, downlink_data_notification_delay)
    },
    [UPDATE_BAR_RESPONSE_DL_BUFFERING_DURATION] = {
      .type = PFCP_IE_DL_BUFFERING_DURATION,
      .offset = offsetof(pfcp_update_bar_response_t, dl_buffering_duration)
    },
    [UPDATE_BAR_RESPONSE_DL_BUFFERING_SUGGESTED_PACKET_COUNT] = {
      .type = PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT,
      .offset = offsetof(pfcp_update_bar_response_t, dl_buffering_suggested_packet_count)
    },
    [UPDATE_BAR_RESPONSE_SUGGESTED_BUFFERING_PACKETS_COUNT] = {
      .type = PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT,
      .offset = offsetof(pfcp_update_bar_response_t, suggested_buffering_packets_count)
    },
  };

static struct pfcp_group_ie_def pfcp_update_urr_group[] =
  {
    [UPDATE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_update_urr_t, urr_id)
    },
    [UPDATE_URR_MEASUREMENT_METHOD] = {
      .type = PFCP_IE_MEASUREMENT_METHOD,
      .offset = offsetof(pfcp_update_urr_t, measurement_method)
    },
    [UPDATE_URR_REPORTING_TRIGGERS] = {
      .type = PFCP_IE_REPORTING_TRIGGERS,
      .offset = offsetof(pfcp_update_urr_t, reporting_triggers)
    },
    [UPDATE_URR_MEASUREMENT_PERIOD] = {
      .type = PFCP_IE_MEASUREMENT_PERIOD,
      .offset = offsetof(pfcp_update_urr_t, measurement_period)
    },
    [UPDATE_URR_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, volume_threshold)
    },
    [UPDATE_URR_VOLUME_QUOTA] = {
      .type = PFCP_IE_VOLUME_QUOTA,
      .offset = offsetof(pfcp_update_urr_t, volume_quota)
    },
    [UPDATE_URR_TIME_THRESHOLD] = {
      .type = PFCP_IE_TIME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, time_threshold)
    },
    [UPDATE_URR_TIME_QUOTA] = {
      .type = PFCP_IE_TIME_QUOTA,
      .offset = offsetof(pfcp_update_urr_t, time_quota)
    },
    [UPDATE_URR_QUOTA_HOLDING_TIME] = {
      .type = PFCP_IE_QUOTA_HOLDING_TIME,
      .offset = offsetof(pfcp_update_urr_t, quota_holding_time)
    },
    [UPDATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD] = {
      .type = PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, dropped_dl_traffic_threshold)
    },
    [UPDATE_URR_MONITORING_TIME] = {
      .type = PFCP_IE_MONITORING_TIME,
      .offset = offsetof(pfcp_update_urr_t, monitoring_time)
    },
    [UPDATE_URR_SUBSEQUENT_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, subsequent_volume_threshold)
    },
    [UPDATE_URR_SUBSEQUENT_TIME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, subsequent_time_threshold)
    },
    [UPDATE_URR_INACTIVITY_DETECTION_TIME] = {
      .type = PFCP_IE_INACTIVITY_DETECTION_TIME,
      .offset = offsetof(pfcp_update_urr_t, inactivity_detection_time)
    },
    [UPDATE_URR_LINKED_URR_ID] = {
      .type = PFCP_IE_LINKED_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_update_urr_t, linked_urr_id)
    },
    [UPDATE_URR_MEASUREMENT_INFORMATION] = {
      .type = PFCP_IE_MEASUREMENT_INFORMATION,
      .offset = offsetof(pfcp_update_urr_t, measurement_information)
    },
    [UPDATE_URR_TIME_QUOTA_MECHANISM] = {
      .type = PFCP_IE_TIME_QUOTA_MECHANISM,
      .offset = offsetof(pfcp_update_urr_t, time_quota_mechanism)
    },
    [UPDATE_URR_AGGREGATED_URRS] = {
      .type = PFCP_IE_AGGREGATED_URRS,
      .offset = offsetof(pfcp_update_urr_t, aggregated_urrs)
    },
    [UPDATE_URR_FAR_ID_FOR_QUOTE_ACTION] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_urr_t, far_id_for_quota_action)
    },
    [UPDATE_URR_ETHERNET_INACTIVITY_TIMER] = {
      .type = PFCP_IE_ETHERNET_INACTIVITY_TIMER,
      .offset = offsetof(pfcp_update_urr_t, ethernet_inactivity_timer)
    },
  };

static struct pfcp_group_ie_def pfcp_update_qer_group[] =
  {
    [UPDATE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_update_qer_t, qer_id)
    },
    [UPDATE_QER_QER_CORRELATION_ID] = {
      .type = PFCP_IE_QER_CORRELATION_ID,
      .offset = offsetof(pfcp_update_qer_t, qer_correlation_id)
    },
    [UPDATE_QER_GATE_STATUS] = {
      .type = PFCP_IE_GATE_STATUS,
      .offset = offsetof(pfcp_update_qer_t, gate_status)
    },
    [UPDATE_QER_MBR] = {
      .type = PFCP_IE_MBR,
      .offset = offsetof(pfcp_update_qer_t, mbr)
    },
    [UPDATE_QER_GBR] = {
      .type = PFCP_IE_GBR,
      .offset = offsetof(pfcp_update_qer_t, gbr)
    },
    [UPDATE_QER_PACKET_RATE] = {
      .type = PFCP_IE_PACKET_RATE,
      .offset = offsetof(pfcp_update_qer_t, packet_rate)
    },
    [UPDATE_QER_DL_FLOW_LEVEL_MARKING] = {
      .type = PFCP_IE_DL_FLOW_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_qer_t, dl_flow_level_marking)
    },
    [UPDATE_QER_QOS_FLOW_IDENTIFIER] = {
      .type = PFCP_IE_QFI,
      .offset = offsetof(pfcp_update_qer_t, qos_flow_identifier)
    },
    [UPDATE_QER_REFLECTIVE_QOS] = {
      .type = PFCP_IE_RQI,
      .offset = offsetof(pfcp_update_qer_t, reflective_qos)
    },
    [UPDATE_QER_PAGING_POLICY_INDICATOR] = {
      .type = PFCP_IE_PAGING_POLICY_INDICATOR,
      .offset = offsetof(pfcp_update_qer_t, paging_policy_indicator)
    },
    [UPDATE_QER_AVERAGING_WINDOW] = {
      .type = PFCP_IE_AVERAGING_WINDOW,
      .offset = offsetof(pfcp_update_qer_t, averaging_window)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_pdr_group[] =
  {
    [REMOVE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_remove_pdr_t, pdr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_far_group[] =
  {
    [REMOVE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_remove_far_t, far_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_urr_group[] =
  {
    [REMOVE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_remove_urr_t, urr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_qer_group[] =
  {
    [REMOVE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_remove_qer_t, qer_id)
    },
  };

static struct pfcp_group_ie_def pfcp_load_control_information_group[] =
  {
    [LOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER] = {
      .type = PFCP_IE_SEQUENCE_NUMBER,
      .offset = offsetof(pfcp_load_control_information_t, sequence_number)
    },
    [LOAD_CONTROL_INFORMATION_METRIC] = {
      .type = PFCP_IE_METRIC,
      .offset = offsetof(pfcp_load_control_information_t, metric)
    },
  };

static struct pfcp_group_ie_def pfcp_overload_control_information_group[] =
  {
    [OVERLOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER] = {
      .type = PFCP_IE_SEQUENCE_NUMBER,
      .offset = offsetof(pfcp_overload_control_information_t, sequence_number)
    },
    [OVERLOAD_CONTROL_INFORMATION_METRIC] = {
      .type = PFCP_IE_METRIC,
      .offset = offsetof(pfcp_overload_control_information_t, metric)
    },
    [OVERLOAD_CONTROL_INFORMATION_TIMER] = {
      .type = PFCP_IE_TIMER,
      .offset = offsetof(pfcp_overload_control_information_t, timer)
    },
    [OVERLOAD_CONTROL_INFORMATION_OCI_FLAGS] = {
      .type = PFCP_IE_OCI_FLAGS,
      .offset = offsetof(pfcp_overload_control_information_t, oci_flags)
    },
  };

static struct pfcp_group_ie_def pfcp_application_id_pfds_group[] =
  {
    [APPLICATION_ID_PFDS_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_application_id_pfds_t, application_id)
    },
    [APPLICATION_ID_PFDS_PFD] = {
      .type = PFCP_IE_PFD,
      .is_array = true,
      .offset = offsetof(pfcp_application_id_pfds_t, pfd)
    },
  };

static struct pfcp_group_ie_def pfcp_pfd_group[] =
  {
    [PFD_PFD_CONTENTS] = {
      .type = PFCP_IE_PFD_CONTENTS,
      .is_array = true,
      .offset = offsetof(pfcp_pfd_t, pfd_contents)
    },
  };

static struct pfcp_group_ie_def pfcp_application_detection_information_group[] =
  {
    [APPLICATION_DETECTION_INFORMATION_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_application_detection_information_t, application_id)
    },
    [APPLICATION_DETECTION_INFORMATION_APPLICATION_INSTANCE_ID] = {
      .type = PFCP_IE_APPLICATION_INSTANCE_ID,
      .offset = offsetof(pfcp_application_detection_information_t, application_instance_id)
    },
    [APPLICATION_DETECTION_INFORMATION_FLOW_INFORMATION] = {
      .type = PFCP_IE_FLOW_INFORMATION,
      .offset = offsetof(pfcp_application_detection_information_t, flow_information)
    },
  };

static struct pfcp_group_ie_def pfcp_query_urr_group[] =
  {
    [QUERY_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_query_urr_t, urr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_smr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
    [USAGE_REPORT_QUERY_URR_REFERENCE] = {
      .type = PFCP_IE_QUERY_URR_REFERENCE,
      .offset = offsetof(pfcp_usage_report_t, query_urr_reference)
    },
    [USAGE_REPORT_EVENT_TIME_STAMP] = {
      .type = PFCP_IE_EVENT_TIME_STAMP,
      .is_array = true,
      .offset = offsetof(pfcp_usage_report_t, event_time_stamp)
    },
    [USAGE_REPORT_ETHERNET_TRAFFIC_INFORMATION] = {
      .type = PFCP_IE_ETHERNET_TRAFFIC_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, ethernet_traffic_information)
    },
    [USAGE_REPORT_TP_NOW] = {
      .type = PFCP_IE_TP_NOW,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_now)
    },
    [USAGE_REPORT_TP_START_TIME] = {
      .type = PFCP_IE_TP_START_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_start_time)
    },
    [USAGE_REPORT_TP_END_TIME] = {
      .type = PFCP_IE_TP_END_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_end_time)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_sdr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
    [USAGE_REPORT_ETHERNET_TRAFFIC_INFORMATION] = {
      .type = PFCP_IE_ETHERNET_TRAFFIC_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, ethernet_traffic_information)
    },
    [USAGE_REPORT_TP_NOW] = {
      .type = PFCP_IE_TP_NOW,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_now)
    },
    [USAGE_REPORT_TP_START_TIME] = {
      .type = PFCP_IE_TP_START_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_start_time)
    },
    [USAGE_REPORT_TP_END_TIME] = {
      .type = PFCP_IE_TP_END_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_end_time)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_srr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_APPLICATION_DETECTION_INFORMATION] = {
      .type = PFCP_IE_APPLICATION_DETECTION_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, application_detection_information)
    },
    [USAGE_REPORT_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_usage_report_t, ue_ip_address)
    },
    [USAGE_REPORT_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_usage_report_t, network_instance)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
    [USAGE_REPORT_QUERY_URR_REFERENCE] = {
      .type = PFCP_IE_QUERY_URR_REFERENCE,
      .offset = offsetof(pfcp_usage_report_t, query_urr_reference)
    },
    [USAGE_REPORT_ETHERNET_TRAFFIC_INFORMATION] = {
      .type = PFCP_IE_ETHERNET_TRAFFIC_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, ethernet_traffic_information)
    },
    [USAGE_REPORT_TP_NOW] = {
      .type = PFCP_IE_TP_NOW,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_now)
    },
    [USAGE_REPORT_TP_START_TIME] = {
      .type = PFCP_IE_TP_START_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_start_time)
    },
    [USAGE_REPORT_TP_END_TIME] = {
      .type = PFCP_IE_TP_END_TIME,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_usage_report_t, tp_end_time)
    },
  };

static struct pfcp_group_ie_def pfcp_downlink_data_report_group[] =
  {
    [DOWNLINK_DATA_REPORT_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_downlink_data_report_t, pdr_id)
    },
    [DOWNLINK_DATA_REPORT_DOWNLINK_DATA_SERVICE_INFORMATION] = {
      .type = PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_downlink_data_report_t, downlink_data_service_information)
    },
  };

static struct pfcp_group_ie_def pfcp_create_bar_group[] =
  {
    [CREATE_BAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_create_bar_t, bar_id)
    },
    [CREATE_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_create_bar_t, downlink_data_notification_delay)
    },
    [CREATE_BAR_SUGGESTED_BUFFERING_PACKETS_COUNT] = {
      .type = PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT,
      .offset = offsetof(pfcp_create_bar_t, suggested_buffering_packets_count)
    },
  };

static struct pfcp_group_ie_def pfcp_update_bar_request_group[] =
  {
    [UPDATE_BAR_REQUEST_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_bar_request_t, bar_id)
    },
    [UPDATE_BAR_REQUEST_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_update_bar_request_t, downlink_data_notification_delay)
    },
    [UPDATE_BAR_REQUEST_SUGGESTED_BUFFERING_PACKETS_COUNT] = {
      .type = PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT,
      .offset = offsetof(pfcp_update_bar_request_t, suggested_buffering_packets_count)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_bar_group[] =
  {
    [REMOVE_BAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_remove_bar_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_error_indication_report_group[] =
  {
    [ERROR_INDICATION_REPORT_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .is_array = true,
      .offset = offsetof(pfcp_error_indication_report_t, f_teid)
    },
  };

static struct pfcp_group_ie_def pfcp_user_plane_path_failure_report_group[] =
  {
    [USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER] = {
      .type = PFCP_IE_REMOTE_GTP_U_PEER,
      .is_array = true,
      .offset = offsetof(pfcp_user_plane_path_failure_report_t, remote_gtp_u_peer)
    },
  };

static struct pfcp_group_ie_def pfcp_update_duplicating_parameters_group[] =
  {
    [UPDATE_DUPLICATING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, destination_interface)
    },
    [UPDATE_DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, outer_header_creation)
    },
    [UPDATE_DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, transport_level_marking)
    },
    [UPDATE_DUPLICATING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, forwarding_policy)
    },
  };

static struct pfcp_group_ie_def pfcp_aggregated_urrs_group[] =
  {
    [AGGREGATED_URRS_AGGREGATED_URR_ID] = {
      .type = PFCP_IE_AGGREGATED_URR_ID,
      .offset = offsetof(pfcp_aggregated_urrs_t, aggregated_urr_id)
    },
    [AGGREGATED_URRS_MULTIPLIER] = {
      .type = PFCP_IE_MULTIPLIER,
      .offset = offsetof(pfcp_aggregated_urrs_t, multiplier)
    },
  };

static struct pfcp_group_ie_def pfcp_create_traffic_endpoint_group[] =
  {
    [CREATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_create_traffic_endpoint_t, traffic_endpoint_id)
    },
    [CREATE_TRAFFIC_ENDPOINT_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_create_traffic_endpoint_t, f_teid)
    },
    [CREATE_TRAFFIC_ENDPOINT_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_create_traffic_endpoint_t, network_instance)
    },
    [CREATE_TRAFFIC_ENDPOINT_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_create_traffic_endpoint_t, ue_ip_address)
    },
    [CREATE_TRAFFIC_ENDPOINT_ETHERNET_PDU_SESSION_INFORMATION] = {
      .type = PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION,
      .offset = offsetof(pfcp_create_traffic_endpoint_t, ethernet_pdu_session_information)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_ROUTE] = {
      .type = PFCP_IE_FRAMED_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_route)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_ROUTING] = {
      .type = PFCP_IE_FRAMED_ROUTING,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_routing)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_IPV6_ROUTE] = {
      .type = PFCP_IE_FRAMED_IPV6_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_ipv6_route)
    },
  };

static struct pfcp_group_ie_def pfcp_created_traffic_endpoint_group[] =
  {
    [CREATED_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_created_traffic_endpoint_t, traffic_endpoint_id)
    },
    [CREATED_TRAFFIC_ENDPOINT_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_created_traffic_endpoint_t, f_teid)
    },
    [CREATED_TRAFFIC_ENDPOINT_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_created_traffic_endpoint_t, ue_ip_address)
    },
  };

static struct pfcp_group_ie_def pfcp_update_traffic_endpoint_group[] =
  {
    [UPDATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, traffic_endpoint_id)
    },
    [UPDATE_TRAFFIC_ENDPOINT_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, f_teid)
    },
    [UPDATE_TRAFFIC_ENDPOINT_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, network_instance)
    },
    [UPDATE_TRAFFIC_ENDPOINT_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, ue_ip_address)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_ROUTE] = {
      .type = PFCP_IE_FRAMED_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_route)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_ROUTING] = {
      .type = PFCP_IE_FRAMED_ROUTING,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_routing)
    },
    [UPDATE_TRAFFIC_ENDPOINT_FRAMED_IPV6_ROUTE] = {
      .type = PFCP_IE_FRAMED_IPV6_ROUTE,
      .is_array = true,
      .offset = offsetof(pfcp_update_traffic_endpoint_t, framed_ipv6_route)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_traffic_endpoint_group[] =
  {
    [REMOVE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID] = {
      .type = PFCP_IE_TRAFFIC_ENDPOINT_ID,
      .offset = offsetof(pfcp_remove_traffic_endpoint_t, traffic_endpoint_id)
    },
  };

static struct pfcp_group_ie_def pfcp_ethernet_packet_filter_group[] =
  {
    [ETHERNET_PACKET_FILTER_ETHERNET_FILTER_ID] = {
      .type = PFCP_IE_ETHERNET_FILTER_ID,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, ethernet_filter_id)
    },
    [ETHERNET_PACKET_FILTER_ETHERNET_FILTER_PROPERTIES] = {
      .type = PFCP_IE_ETHERNET_FILTER_PROPERTIES,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, ethernet_filter_properties)
    },
    [ETHERNET_PACKET_FILTER_MAC_ADDRESS] = {
      .type = PFCP_IE_MAC_ADDRESS,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, mac_address)
    },
    [ETHERNET_PACKET_FILTER_ETHERTYPE] = {
      .type = PFCP_IE_ETHERTYPE,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, ethertype)
    },
    [ETHERNET_PACKET_FILTER_C_TAG] = {
      .type = PFCP_IE_C_TAG,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, c_tag)
    },
    [ETHERNET_PACKET_FILTER_S_TAG] = {
      .type = PFCP_IE_S_TAG,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, s_tag)
    },
    [ETHERNET_PACKET_FILTER_SDF_FILTER] = {
      .type = PFCP_IE_SDF_FILTER,
      .is_array = true,
      .offset = offsetof(pfcp_ethernet_packet_filter_t, sdf_filter)
    },
  };

static struct pfcp_group_ie_def pfcp_ethernet_traffic_information_group[] =
  {
    [ETHERNET_TRAFFIC_INFORMATION_MAC_ADDRESSES_DETECTED] = {
      .type = PFCP_IE_MAC_ADDRESSES_DETECTED,
      .offset = offsetof(pfcp_ethernet_traffic_information_t, mac_addresses_detected)
    },
    [ETHERNET_TRAFFIC_INFORMATION_MAC_ADDRESSES_REMOVED] = {
      .type = PFCP_IE_MAC_ADDRESSES_REMOVED,
      .offset = offsetof(pfcp_ethernet_traffic_information_t, mac_addresses_removed)
    },
  };

static struct pfcp_group_ie_def pfcp_additional_monitoring_time_group[] =
  {
    [ADDITIONAL_MONITORING_TIME_MONITORING_TIME] = {
      .type = PFCP_IE_MONITORING_TIME,
      .offset = offsetof(pfcp_additional_monitoring_time_t, monitoring_time)
    },
    [ADDITIONAL_MONITORING_TIME_SUBSEQUENT_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_additional_monitoring_time_t, subsequent_volume_threshold)
    },
    [ADDITIONAL_MONITORING_TIME_SUBSEQUENT_TIME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_THRESHOLD,
      .offset = offsetof(pfcp_additional_monitoring_time_t, subsequent_time_threshold)
    },
    [ADDITIONAL_MONITORING_TIME_SUBSEQUENT_VOLUME_QUOTA] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_QUOTA,
      .offset = offsetof(pfcp_additional_monitoring_time_t, subsequent_volume_quota)
    },
    [ADDITIONAL_MONITORING_TIME_SUBSEQUENT_TIME_QUOTA] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_QUOTA,
      .offset = offsetof(pfcp_additional_monitoring_time_t, subsequent_time_quota)
    },
  };

static struct pfcp_group_ie_def pfcp_create_mar_group[] =
  {
    [CREATE_MAR_MAR_ID] = {
      .type = PFCP_IE_MAR_ID,
      .offset = offsetof(pfcp_create_mar_t, mar_id)
    },
    [CREATE_MAR_STEERING_FUNCTIONALITY] = {
      .type = PFCP_IE_STEERING_FUNCTIONALITY,
      .offset = offsetof(pfcp_create_mar_t, steering_functionality)
    },
    [CREATE_MAR_STEERING_MODE] = {
      .type = PFCP_IE_STEERING_MODE,
      .offset = offsetof(pfcp_create_mar_t, steering_mode)
    },
    [CREATE_MAR_ACCESS_FORWARDING_ACTION_INFORMATION_1] = {
      .type = PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_1,
      .offset = offsetof(pfcp_create_mar_t, access_forwarding_action_information_1)
    },
    [CREATE_MAR_ACCESS_FORWARDING_ACTION_INFORMATION_2] = {
      .type = PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_2,
      .offset = offsetof(pfcp_create_mar_t, access_forwarding_action_information_2)
    },
  };

static struct pfcp_group_ie_def pfcp_access_forwarding_action_information_group[] =
  {
    [ACCESS_FORWARDING_ACTION_INFORMATION_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_access_forwarding_action_information_t, far_id)
    },
    [ACCESS_FORWARDING_ACTION_INFORMATION_WEIGHT] = {
      .type = PFCP_IE_WEIGHT,
      .offset = offsetof(pfcp_access_forwarding_action_information_t, weight)
    },
    [ACCESS_FORWARDING_ACTION_INFORMATION_PRIORITY] = {
      .type = PFCP_IE_PRIORITY,
      .offset = offsetof(pfcp_access_forwarding_action_information_t, priority)
    },
    [ACCESS_FORWARDING_ACTION_INFORMATION_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_access_forwarding_action_information_t, urr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_mar_group[] =
  {
    [REMOVE_MAR_MAR_ID] = {
      .type = PFCP_IE_MAR_ID,
      .offset = offsetof(pfcp_remove_mar_t, mar_id)
    },
   };

static struct pfcp_group_ie_def pfcp_update_mar_group[] =
  {
    [UPDATE_MAR_MAR_ID] = {
      .type = PFCP_IE_MAR_ID,
      .offset = offsetof(pfcp_update_mar_t, mar_id)
    },
    [UPDATE_MAR_STEERING_FUNCTIONALITY] = {
      .type = PFCP_IE_STEERING_FUNCTIONALITY,
      .offset = offsetof(pfcp_update_mar_t, steering_functionality)
    },
    [UPDATE_MAR_STEERING_MODE] = {
      .type = PFCP_IE_STEERING_MODE,
      .offset = offsetof(pfcp_update_mar_t, steering_mode)
    },
    [UPDATE_MAR_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1] = {
      .type = PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1,
      .offset = offsetof(pfcp_update_mar_t, update_access_forwarding_action_information_1)
    },
    [UPDATE_MAR_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2] = {
      .type = PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2,
      .offset = offsetof(pfcp_update_mar_t, update_access_forwarding_action_information_2)
    },
    [UPDATE_MAR_ACCESS_FORWARDING_ACTION_INFORMATION_1] = {
      .type = PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_1,
      .offset = offsetof(pfcp_update_mar_t, access_forwarding_action_information_1)
    },
    [UPDATE_MAR_ACCESS_FORWARDING_ACTION_INFORMATION_2] = {
      .type = PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_2,
      .offset = offsetof(pfcp_update_mar_t, access_forwarding_action_information_2)
    },
  };

static struct pfcp_group_ie_def pfcp_update_access_forwarding_action_information_group[] =
  {
    [UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_access_forwarding_action_information_t, far_id)
    },
    [UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_WEIGHT] = {
      .type = PFCP_IE_WEIGHT,
      .offset = offsetof(pfcp_update_access_forwarding_action_information_t, weight)
    },
    [UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_PRIORITY] = {
      .type = PFCP_IE_PRIORITY,
      .offset = offsetof(pfcp_update_access_forwarding_action_information_t, priority)
    },
    [UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_update_access_forwarding_action_information_t, urr_id)
    },
  };

/**********************************************************/

#define SIMPLE_IE(IE, TYPE, NAME)			\
  [IE] = {						\
    .name = NAME,					\
    .length = sizeof(pfcp_ ## TYPE ## _t),		\
    .format = format_ ## TYPE,				\
    .decode = decode_ ## TYPE,				\
    .encode = encode_ ## TYPE,				\
}

#define SIMPLE_IE_FREE(IE, TYPE, NAME)			\
  [IE] = {						\
    .name = NAME,					\
    .length = sizeof(pfcp_ ## TYPE ## _t),		\
    .format = format_ ## TYPE,				\
    .decode = decode_ ## TYPE,				\
    .encode = encode_ ## TYPE,				\
    .free = free_ ## TYPE,				\
}

static struct pfcp_ie_def tgpp_specs[] =
  {
    [PFCP_IE_CREATE_PDR] =
    {
      .name = "Create PDR",
      .length = sizeof(pfcp_create_pdr_t),
      .mandatory = (BIT(CREATE_PDR_PDR_ID) |
		    BIT(CREATE_PDR_PRECEDENCE) |
		    BIT(CREATE_PDR_PDI)),
      .size = ARRAY_LEN(pfcp_create_pdr_group),
      .group = pfcp_create_pdr_group,
    },
    [PFCP_IE_PDI] =
    {
      .name = "PDI",
      .length = sizeof(pfcp_pdi_t),
      .mandatory = BIT(PDI_SOURCE_INTERFACE),
      .size = ARRAY_LEN(pfcp_pdi_group),
      .group = pfcp_pdi_group,
    },
    [PFCP_IE_CREATE_FAR] =
    {
      .name = "Create FAR",
      .length = sizeof(pfcp_create_far_t),
      .mandatory = (BIT(CREATE_FAR_FAR_ID) |
		    BIT(CREATE_FAR_APPLY_ACTION)),
      .size = ARRAY_LEN(pfcp_create_far_group),
      .group = pfcp_create_far_group,
    },
    [PFCP_IE_FORWARDING_PARAMETERS] =
    {
      .name = "Forwarding Parameters",
      .length = sizeof(pfcp_forwarding_parameters_t),
      .mandatory = BIT(FORWARDING_PARAMETERS_DESTINATION_INTERFACE),
      .size = ARRAY_LEN(pfcp_forwarding_parameters_group),
      .group = pfcp_forwarding_parameters_group,
    },
    [PFCP_IE_DUPLICATING_PARAMETERS] =
    {
      .name = "Duplicating Parameters",
      .length = sizeof(pfcp_duplicating_parameters_t),
      .mandatory = BIT(DUPLICATING_PARAMETERS_DESTINATION_INTERFACE),
      .size = ARRAY_LEN(pfcp_duplicating_parameters_group),
      .group = pfcp_duplicating_parameters_group,
    },
    [PFCP_IE_CREATE_URR] =
    {
      .name = "Create URR",
      .length = sizeof(pfcp_create_urr_t),
      .mandatory = (BIT(CREATE_URR_URR_ID) |
		    BIT(CREATE_URR_MEASUREMENT_METHOD) |
		    BIT(CREATE_URR_REPORTING_TRIGGERS)),
      .size = ARRAY_LEN(pfcp_create_urr_group),
      .group = pfcp_create_urr_group,
    },
    [PFCP_IE_CREATE_QER] =
    {
      .name = "Create QER",
      .length = sizeof(pfcp_create_qer_t),
      .mandatory = (BIT(CREATE_QER_QER_ID) |
		    BIT(CREATE_QER_GATE_STATUS)),
      .size = ARRAY_LEN(pfcp_create_qer_group),
      .group = pfcp_create_qer_group,
    },
    [PFCP_IE_CREATED_PDR] =
    {
      .name = "Created PDR",
      .length = sizeof(pfcp_created_pdr_t),
      .mandatory = BIT(CREATED_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_created_pdr_group),
      .group = pfcp_created_pdr_group,
    },
    [PFCP_IE_UPDATE_PDR] =
    {
      .name = "Update PDR",
      .length = sizeof(pfcp_update_pdr_t),
      .mandatory = BIT(UPDATE_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_update_pdr_group),
      .group = pfcp_update_pdr_group,
    },
    [PFCP_IE_UPDATE_FAR] =
    {
      .name = "Update FAR",
      .length = sizeof(pfcp_update_far_t),
      .mandatory = BIT(UPDATE_FAR_FAR_ID),
      .size = ARRAY_LEN(pfcp_update_far_group),
      .group = pfcp_update_far_group,
    },
    [PFCP_IE_UPDATE_FORWARDING_PARAMETERS] =
    {
      .name = "Update Forwarding Parameters",
      .length = sizeof(pfcp_update_forwarding_parameters_t),
      .size = ARRAY_LEN(pfcp_update_forwarding_parameters_group),
      .group = pfcp_update_forwarding_parameters_group,
    },
    [PFCP_IE_UPDATE_BAR_RESPONSE] =
    {
      .name = "Update BAR Response",
      .length = sizeof(pfcp_update_bar_response_t),
      .mandatory = BIT(UPDATE_BAR_RESPONSE_BAR_ID),
      .size = ARRAY_LEN(pfcp_update_bar_response_group),
      .group = pfcp_update_bar_response_group,
    },
    [PFCP_IE_UPDATE_URR] =
    {
      .name = "Update URR",
      .length = sizeof(pfcp_update_urr_t),
      .mandatory = BIT(UPDATE_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_update_urr_group),
      .group = pfcp_update_urr_group,
    },
    [PFCP_IE_UPDATE_QER] =
    {
      .name = "Update QER",
      .length = sizeof(pfcp_update_qer_t),
      .mandatory = BIT(UPDATE_QER_QER_ID),
      .size = ARRAY_LEN(pfcp_update_qer_group),
      .group = pfcp_update_qer_group,
    },
    [PFCP_IE_REMOVE_PDR] =
    {
      .name = "Remove PDR",
      .length = sizeof(pfcp_remove_pdr_t),
      .mandatory = BIT(REMOVE_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_remove_pdr_group),
      .group = pfcp_remove_pdr_group,
    },
    [PFCP_IE_REMOVE_FAR] =
    {
      .name = "Remove FAR",
      .length = sizeof(pfcp_remove_far_t),
      .mandatory = BIT(REMOVE_FAR_FAR_ID),
      .size = ARRAY_LEN(pfcp_remove_far_group),
      .group = pfcp_remove_far_group,
    },
    [PFCP_IE_REMOVE_URR] =
    {
      .name = "Remove URR",
      .length = sizeof(pfcp_remove_urr_t),
      .mandatory = BIT(REMOVE_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_remove_urr_group),
      .group = pfcp_remove_urr_group,
    },
    [PFCP_IE_REMOVE_QER] =
    {
      .name = "Remove QER",
      .length = sizeof(pfcp_remove_qer_t),
      .mandatory = BIT(REMOVE_QER_QER_ID),
      .size = ARRAY_LEN(pfcp_remove_qer_group),
      .group = pfcp_remove_qer_group,
    },
    SIMPLE_IE(PFCP_IE_CAUSE, cause, "Cause"),
    SIMPLE_IE(PFCP_IE_SOURCE_INTERFACE, source_interface, "Source Interface"),
    SIMPLE_IE(PFCP_IE_F_TEID, f_teid, "F-TEID"),
    SIMPLE_IE_FREE(PFCP_IE_NETWORK_INSTANCE, network_instance, "Network Instance"),
    SIMPLE_IE_FREE(PFCP_IE_SDF_FILTER, sdf_filter, "SDF Filter"),
    SIMPLE_IE_FREE(PFCP_IE_APPLICATION_ID, application_id, "Application ID"),
    SIMPLE_IE(PFCP_IE_GATE_STATUS, gate_status, "Gate Status"),
    SIMPLE_IE(PFCP_IE_MBR, mbr, "MBR"),
    SIMPLE_IE(PFCP_IE_GBR, gbr, "GBR"),
    SIMPLE_IE(PFCP_IE_QER_CORRELATION_ID, qer_correlation_id, "QER Correlation ID"),
    SIMPLE_IE(PFCP_IE_PRECEDENCE, precedence, "Precedence"),
    SIMPLE_IE(PFCP_IE_TRANSPORT_LEVEL_MARKING, transport_level_marking,
	      "Transport Level Marking"),
    SIMPLE_IE(PFCP_IE_VOLUME_THRESHOLD, volume_threshold, "Volume Threshold"),
    SIMPLE_IE(PFCP_IE_TIME_THRESHOLD, time_threshold, "Time Threshold"),
    SIMPLE_IE(PFCP_IE_MONITORING_TIME, monitoring_time, "Monitoring Time"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD, subsequent_volume_threshold,
	      "Subsequent Volume Threshold"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_TIME_THRESHOLD, subsequent_time_threshold,
	      "Subsequent Time Threshold"),
    SIMPLE_IE(PFCP_IE_INACTIVITY_DETECTION_TIME, inactivity_detection_time,
	      "Inactivity Detection Time"),
    SIMPLE_IE(PFCP_IE_REPORTING_TRIGGERS, reporting_triggers, "Reporting Triggers"),
    SIMPLE_IE_FREE(PFCP_IE_REDIRECT_INFORMATION, redirect_information, "Redirect Information"),
    SIMPLE_IE(PFCP_IE_REPORT_TYPE, report_type, "Report Type"),
    SIMPLE_IE(PFCP_IE_OFFENDING_IE, offending_ie, "Offending IE"),
    SIMPLE_IE(PFCP_IE_FORWARDING_POLICY, forwarding_policy, "Forwarding Policy"),
    SIMPLE_IE(PFCP_IE_DESTINATION_INTERFACE, destination_interface, "Destination Interface"),
    SIMPLE_IE(PFCP_IE_UP_FUNCTION_FEATURES, up_function_features, "UP Function Features"),
    SIMPLE_IE(PFCP_IE_APPLY_ACTION, apply_action, "Apply Action"),
    SIMPLE_IE(PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION, downlink_data_service_information,
	      "Downlink Data Service Information"),
    SIMPLE_IE(PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY, downlink_data_notification_delay,
	      "Downlink Data Notification Delay"),
    SIMPLE_IE(PFCP_IE_DL_BUFFERING_DURATION, dl_buffering_duration, "DL Buffering Duration"),
    SIMPLE_IE(PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT, dl_buffering_suggested_packet_count,
	      "DL Buffering Suggested Packet Count"),
    SIMPLE_IE(PFCP_IE_PFCPSMREQ_FLAGS, pfcpsmreq_flags, "PFCPSMReq-Flags"),
    SIMPLE_IE(PFCP_IE_PFCPSRRSP_FLAGS, pfcpsrrsp_flags, "PFCPSRRsp-Flags"),


    [PFCP_IE_LOAD_CONTROL_INFORMATION] =
    {
      .name = "Load Control Information",
      .length = sizeof(pfcp_load_control_information_t),
      .mandatory = (BIT(LOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER) |
		    BIT(LOAD_CONTROL_INFORMATION_METRIC)),
      .size = ARRAY_LEN(pfcp_load_control_information_group),
      .group = pfcp_load_control_information_group,
    },
    SIMPLE_IE(PFCP_IE_SEQUENCE_NUMBER, sequence_number, "Sequence Number"),
    SIMPLE_IE(PFCP_IE_METRIC, metric, "Metric"),
    [PFCP_IE_OVERLOAD_CONTROL_INFORMATION] =
    {
      .name = "Overload Control Information",
      .length = sizeof(pfcp_overload_control_information_t),
      .mandatory = (BIT(OVERLOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER) |
		    BIT(OVERLOAD_CONTROL_INFORMATION_METRIC) |
		    BIT(OVERLOAD_CONTROL_INFORMATION_TIMER)),
      .size = ARRAY_LEN(pfcp_overload_control_information_group),
      .group = pfcp_overload_control_information_group,
    },
    SIMPLE_IE(PFCP_IE_TIMER, timer, "Timer"),
    SIMPLE_IE(PFCP_IE_PDR_ID, pdr_id, "PDR Id"),
    SIMPLE_IE(PFCP_IE_F_SEID, f_seid, "F-SEID"),
    [PFCP_IE_APPLICATION_ID_PFDS] =
    {
      .name = "Application ID PFDs",
      .length = sizeof(pfcp_application_id_pfds_t),
      .mandatory = BIT(APPLICATION_ID_PFDS_APPLICATION_ID),
      .size = ARRAY_LEN(pfcp_application_id_pfds_group),
      .group = pfcp_application_id_pfds_group,
    },
    [PFCP_IE_PFD] =
    {
      .name = "PFD",
      .length = sizeof(pfcp_pfd_t),
      .mandatory = BIT(PFD_PFD_CONTENTS),
      .size = ARRAY_LEN(pfcp_pfd_group),
      .group = pfcp_pfd_group,
    },
    SIMPLE_IE_FREE(PFCP_IE_NODE_ID, node_id, "Node ID"),
    SIMPLE_IE_FREE(PFCP_IE_PFD_CONTENTS, pfd_contents, "PFD contents"),
    SIMPLE_IE(PFCP_IE_MEASUREMENT_METHOD, measurement_method, "Measurement Method"),
    SIMPLE_IE(PFCP_IE_USAGE_REPORT_TRIGGER, usage_report_trigger, "Usage Report Trigger"),
    SIMPLE_IE(PFCP_IE_MEASUREMENT_PERIOD, measurement_period, "Measurement Period"),
    SIMPLE_IE(PFCP_IE_FQ_CSID, fq_csid, "FQ-CSID"),
    SIMPLE_IE(PFCP_IE_VOLUME_MEASUREMENT, volume_measurement, "Volume Measurement"),
    SIMPLE_IE(PFCP_IE_DURATION_MEASUREMENT, duration_measurement, "Duration Measurement"),
    [PFCP_IE_APPLICATION_DETECTION_INFORMATION] =
    {
      .name = "Application Detection Information",
      .length = sizeof(pfcp_application_detection_information_t),
      .mandatory = BIT(APPLICATION_DETECTION_INFORMATION_APPLICATION_ID),
      .size = ARRAY_LEN(pfcp_application_detection_information_group),
      .group = pfcp_application_detection_information_group,
    },
    SIMPLE_IE(PFCP_IE_TIME_OF_FIRST_PACKET, time_of_first_packet, "Time of First Packet"),
    SIMPLE_IE(PFCP_IE_TIME_OF_LAST_PACKET, time_of_last_packet, "Time of Last Packet"),
    SIMPLE_IE(PFCP_IE_QUOTA_HOLDING_TIME, quota_holding_time, "Quota Holding Time"),
    SIMPLE_IE(PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD, dropped_dl_traffic_threshold,
	      "Dropped DL Traffic Threshold"),
    SIMPLE_IE(PFCP_IE_VOLUME_QUOTA, volume_quota, "Volume Quota"),
    SIMPLE_IE(PFCP_IE_TIME_QUOTA, time_quota, "Time Quota"),
    SIMPLE_IE(PFCP_IE_START_TIME, start_time, "Start Time"),
    SIMPLE_IE(PFCP_IE_END_TIME, end_time, "End Time"),
    [PFCP_IE_QUERY_URR] =
    {
      .name = "Query URR",
      .length = sizeof(pfcp_query_urr_t),
      .mandatory = BIT(QUERY_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_query_urr_group),
      .group = pfcp_query_urr_group,
    },
    [PFCP_IE_USAGE_REPORT_SMR] =
    {
      .name = "Usage Report SMR",
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_smr_group),
      .group = pfcp_usage_report_smr_group,
    },
    [PFCP_IE_USAGE_REPORT_SDR] =
    {
      .name = "Usage Report SDR",
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_sdr_group),
      .group = pfcp_usage_report_sdr_group,
    },
    [PFCP_IE_USAGE_REPORT_SRR] =
    {
      .name = "Usage Report SRR",
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_srr_group),
      .group = pfcp_usage_report_srr_group,
    },
    SIMPLE_IE(PFCP_IE_URR_ID, urr_id, "URR ID"),
    SIMPLE_IE(PFCP_IE_LINKED_URR_ID, linked_urr_id, "Linked URR ID"),
    [PFCP_IE_DOWNLINK_DATA_REPORT] =
    {
      .name = "Downlink Data Report",
      .length = sizeof(pfcp_downlink_data_report_t),
      .mandatory = BIT(DOWNLINK_DATA_REPORT_PDR_ID),
      .size = ARRAY_LEN(pfcp_downlink_data_report_group),
      .group = pfcp_downlink_data_report_group,
    },
    SIMPLE_IE(PFCP_IE_OUTER_HEADER_CREATION, outer_header_creation, "Outer Header Creation"),
    [PFCP_IE_CREATE_BAR] =
    {
      .name = "Create BAR",
      .length = sizeof(pfcp_create_bar_t),
      .mandatory = BIT(CREATE_BAR_BAR_ID),
      .size = ARRAY_LEN(pfcp_create_bar_group),
      .group = pfcp_create_bar_group,
    },
    [PFCP_IE_UPDATE_BAR_REQUEST] =
    {
      .name = "Update BAR Request",
      .length = sizeof(pfcp_update_bar_request_t),
      .mandatory = BIT(UPDATE_BAR_REQUEST_BAR_ID),
      .size = ARRAY_LEN(pfcp_update_bar_request_group),
      .group = pfcp_update_bar_request_group,
    },
    [PFCP_IE_REMOVE_BAR] =
    {
      .name = "Remove BAR",
      .length = sizeof(pfcp_remove_bar_t),
      .mandatory = BIT(REMOVE_BAR_BAR_ID),
      .size = ARRAY_LEN(pfcp_remove_bar_group),
      .group = pfcp_remove_bar_group,
    },
    SIMPLE_IE(PFCP_IE_BAR_ID, bar_id, "BAR ID"),
    SIMPLE_IE(PFCP_IE_CP_FUNCTION_FEATURES, cp_function_features, "CP Function Features"),
    SIMPLE_IE(PFCP_IE_USAGE_INFORMATION, usage_information, "Usage Information"),
    SIMPLE_IE_FREE(PFCP_IE_APPLICATION_INSTANCE_ID, application_instance_id,
		   "Application Instance ID"),
    SIMPLE_IE_FREE(PFCP_IE_FLOW_INFORMATION, flow_information, "Flow Information"),
    SIMPLE_IE(PFCP_IE_UE_IP_ADDRESS, ue_ip_address, "UE IP Address"),
    SIMPLE_IE(PFCP_IE_PACKET_RATE, packet_rate, "Packet Rate"),
    SIMPLE_IE(PFCP_IE_OUTER_HEADER_REMOVAL, outer_header_removal, "Outer Header Removal"),
    SIMPLE_IE(PFCP_IE_RECOVERY_TIME_STAMP, recovery_time_stamp, "Recovery Time Stamp"),
    SIMPLE_IE(PFCP_IE_DL_FLOW_LEVEL_MARKING, dl_flow_level_marking, "DL Flow Level Marking"),
    SIMPLE_IE(PFCP_IE_HEADER_ENRICHMENT, header_enrichment, "Header Enrichment"),
    [PFCP_IE_ERROR_INDICATION_REPORT] =
    {
      .name = "Error Indication Report",
      .length = sizeof(pfcp_error_indication_report_t),
      .mandatory = BIT(ERROR_INDICATION_REPORT_F_TEID),
      .size = ARRAY_LEN(pfcp_error_indication_report_group),
      .group = pfcp_error_indication_report_group,
    },
    SIMPLE_IE(PFCP_IE_MEASUREMENT_INFORMATION, measurement_information,
	      "Measurement Information"),
    SIMPLE_IE(PFCP_IE_NODE_REPORT_TYPE, node_report_type, "Node Report Type"),
    [PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT] =
    {
      .name = "User Plane Path Failure Report",
      .length = sizeof(pfcp_user_plane_path_failure_report_t),
      .mandatory = BIT(USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER),
      .size = ARRAY_LEN(pfcp_user_plane_path_failure_report_group),
      .group = pfcp_user_plane_path_failure_report_group,
    },
    SIMPLE_IE(PFCP_IE_REMOTE_GTP_U_PEER, remote_gtp_u_peer, "Remote GTP-U Peer"),
    SIMPLE_IE(PFCP_IE_UR_SEQN, ur_seqn, "UR-SEQN"),
    [PFCP_IE_UPDATE_DUPLICATING_PARAMETERS] =
    {
      .name = "Update Duplicating Parameters",
      .length = sizeof(pfcp_update_duplicating_parameters_t),
      .size = ARRAY_LEN(pfcp_update_duplicating_parameters_group),
      .group = pfcp_update_duplicating_parameters_group,
    },
    SIMPLE_IE_FREE(PFCP_IE_ACTIVATE_PREDEFINED_RULES, activate_predefined_rules,
		   "Activate Predefined Rules"),
    SIMPLE_IE_FREE(PFCP_IE_DEACTIVATE_PREDEFINED_RULES, deactivate_predefined_rules,
		   "Deactivate Predefined Rules"),
    SIMPLE_IE(PFCP_IE_FAR_ID, far_id, "FAR ID"),
    SIMPLE_IE(PFCP_IE_QER_ID, qer_id, "QER ID"),
    SIMPLE_IE(PFCP_IE_OCI_FLAGS, oci_flags, "OCI Flags"),
    SIMPLE_IE(PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST, pfcp_association_release_request,
	      "PFCP Association Release Request"),
    SIMPLE_IE(PFCP_IE_GRACEFUL_RELEASE_PERIOD, graceful_release_period,
	      "Graceful Release Period"),
    SIMPLE_IE(PFCP_IE_PDN_TYPE, pdn_type, "PDN Type"),
    SIMPLE_IE(PFCP_IE_FAILED_RULE_ID, failed_rule_id, "Failed Rule ID"),
    SIMPLE_IE(PFCP_IE_TIME_QUOTA_MECHANISM, time_quota_mechanism, "Time Quota Mechanism"),
    SIMPLE_IE_FREE(PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
		   user_plane_ip_resource_information, "User Plane IP Resource Information"),
    SIMPLE_IE(PFCP_IE_USER_PLANE_INACTIVITY_TIMER, user_plane_inactivity_timer,
	      "User Plane Inactivity Timer"),
    [PFCP_IE_AGGREGATED_URRS] =
    {
      .name = "Aggregated URRs",
      .length = sizeof(pfcp_aggregated_urrs_t),
      .mandatory = (BIT(AGGREGATED_URRS_AGGREGATED_URR_ID) |
		    BIT(AGGREGATED_URRS_MULTIPLIER)),
      .size = ARRAY_LEN(pfcp_aggregated_urrs_group),
      .group = pfcp_aggregated_urrs_group,
    },
    SIMPLE_IE(PFCP_IE_MULTIPLIER, multiplier, "Multiplier"),
    SIMPLE_IE(PFCP_IE_AGGREGATED_URR_ID, aggregated_urr_id, "Aggregated URR ID"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_VOLUME_QUOTA, subsequent_volume_quota,
	      "Subsequent Volume Quota"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_TIME_QUOTA, subsequent_time_quota, "Subsequent Time Quota"),
    SIMPLE_IE(PFCP_IE_RQI, rqi, "RQI"),
    SIMPLE_IE(PFCP_IE_QFI, qfi, "QFI"),
    SIMPLE_IE(PFCP_IE_QUERY_URR_REFERENCE, query_urr_reference, "Query URR Reference"),
    SIMPLE_IE(PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,
	      additional_usage_reports_information, "Additional Usage Reports Information"),
    [PFCP_IE_CREATE_TRAFFIC_ENDPOINT] =
    {
      .name = "Create Traffic Endpoint",
      .length = sizeof(pfcp_create_traffic_endpoint_t),
      .mandatory = BIT(CREATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID),
      .size = ARRAY_LEN(pfcp_create_traffic_endpoint_group),
      .group = pfcp_create_traffic_endpoint_group,
    },
    [PFCP_IE_CREATED_TRAFFIC_ENDPOINT] =
    {
      .name = "Created Traffic Endpoint",
      .length = sizeof(pfcp_created_traffic_endpoint_t),
      .mandatory = BIT(CREATED_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID),
      .size = ARRAY_LEN(pfcp_created_traffic_endpoint_group),
      .group = pfcp_created_traffic_endpoint_group,
    },
    [PFCP_IE_UPDATE_TRAFFIC_ENDPOINT] =
    {
      .name = "Update Traffic Endpoint",
      .length = sizeof(pfcp_update_traffic_endpoint_t),
      .mandatory = BIT(UPDATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID),
      .size = ARRAY_LEN(pfcp_update_traffic_endpoint_group),
      .group = pfcp_update_traffic_endpoint_group,
    },
    [PFCP_IE_REMOVE_TRAFFIC_ENDPOINT] =
    {
      .name = "Remove Traffic Endpoint",
      .length = sizeof(pfcp_remove_traffic_endpoint_t),
      .mandatory = BIT(REMOVE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID),
      .size = ARRAY_LEN(pfcp_remove_traffic_endpoint_group),
      .group = pfcp_remove_traffic_endpoint_group,
    },
    SIMPLE_IE(PFCP_IE_TRAFFIC_ENDPOINT_ID, traffic_endpoint_id, "Traffic Endpoint ID"),
    [PFCP_IE_ETHERNET_PACKET_FILTER] =
    {
      .name = "Ethernet Packet Filter",
      .length = sizeof(pfcp_ethernet_packet_filter_t),
      .size = ARRAY_LEN(pfcp_ethernet_packet_filter_group),
      .group = pfcp_ethernet_packet_filter_group,
    },
    [PFCP_IE_MAC_ADDRESS] = {
      .name = "MAC address",
      .length = sizeof(pfcp_mac_address_t),
      .format = format_pfcp_mac_address,
      .decode = decode_pfcp_mac_address,
      .encode = encode_pfcp_mac_address,
    },
    SIMPLE_IE(PFCP_IE_C_TAG, c_tag, "C-TAG"),
    SIMPLE_IE(PFCP_IE_S_TAG, s_tag, "S-TAG"),
    SIMPLE_IE(PFCP_IE_ETHERTYPE, ethertype, "Ethertype"),
    SIMPLE_IE(PFCP_IE_PROXYING, proxying, "Proxying"),
    SIMPLE_IE(PFCP_IE_ETHERNET_FILTER_ID, ethernet_filter_id, "Ethernet Filter ID"),
    SIMPLE_IE(PFCP_IE_ETHERNET_FILTER_PROPERTIES, ethernet_filter_properties,
	      "Ethernet Filter Properties"),
    SIMPLE_IE(PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT, suggested_buffering_packets_count,
	      "Suggested Buffering Packets Count"),
    SIMPLE_IE_FREE(PFCP_IE_USER_ID, user_id, "User ID"),
    SIMPLE_IE(PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION, ethernet_pdu_session_information,
	      "Ethernet PDU Session Information"),
    [PFCP_IE_ETHERNET_TRAFFIC_INFORMATION] =
    {
      .name = "Ethernet Traffic Information",
      .length = sizeof(pfcp_ethernet_traffic_information_t),
      .size = ARRAY_LEN(pfcp_ethernet_traffic_information_group),
      .group = pfcp_ethernet_traffic_information_group,
    },
    SIMPLE_IE_FREE(PFCP_IE_MAC_ADDRESSES_DETECTED, mac_addresses_detected,
		   "MAC Addresses Detected"),
    SIMPLE_IE_FREE(PFCP_IE_MAC_ADDRESSES_REMOVED, mac_addresses_removed,
		   "MAC Addresses Removed"),
    SIMPLE_IE(PFCP_IE_ETHERNET_INACTIVITY_TIMER, ethernet_inactivity_timer,
	      "Ethernet Inactivity Timer"),
    [PFCP_IE_ADDITIONAL_MONITORING_TIME] =
    {
      .name = "Additional Monitoring Time",
      .length = sizeof(pfcp_additional_monitoring_time_t),
      .size = ARRAY_LEN(pfcp_additional_monitoring_time_group),
      .group = pfcp_additional_monitoring_time_group,
    },
    SIMPLE_IE(PFCP_IE_EVENT_QUOTA, event_quota, "Event Quota"),
    SIMPLE_IE(PFCP_IE_EVENT_THRESHOLD, event_threshold, "Event Threshold"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_EVENT_QUOTA, subsequent_event_quota, "Subsequent Event Quota"),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD, subsequent_event_threshold, "Subsequent Event Threshold"),
    SIMPLE_IE_FREE(PFCP_IE_TRACE_INFORMATION, trace_information, "Trace Information"),
    SIMPLE_IE(PFCP_IE_FRAMED_ROUTE, framed_route, "Framed Route"),
    SIMPLE_IE(PFCP_IE_FRAMED_ROUTING, framed_routing, "Framed Routing"),
    SIMPLE_IE(PFCP_IE_FRAMED_IPV6_ROUTE, framed_ipv6_route, "Framed IPv6 Route"),
    SIMPLE_IE(PFCP_IE_EVENT_TIME_STAMP, event_time_stamp, "Event Time Stamp"),
    SIMPLE_IE(PFCP_IE_AVERAGING_WINDOW, averaging_window, "Averaging Window"),
    SIMPLE_IE(PFCP_IE_PAGING_POLICY_INDICATOR, paging_policy_indicator, "Paging Policy Indicator"),
    SIMPLE_IE(PFCP_IE_APN_DNN, apn_dnn, "APN/DNN"),
    SIMPLE_IE(PFCP_IE_TGPP_INTERFACE_TYPE, tgpp_interface_type, "3GPP Interface Type"),
    SIMPLE_IE(PFCP_IE_PFCPSRREQ_FLAGS, pfcpsrreq_flags, "PFCPSRReq-Flags"),
    SIMPLE_IE(PFCP_IE_PFCPAUREQ_FLAGS, pfcpaureq_flags, "PFCPAUReq-Flags"),
    SIMPLE_IE(PFCP_IE_ACTIVATION_TIME, activation_time, "Activation Time"),
    SIMPLE_IE(PFCP_IE_DEACTIVATION_TIME, deactivation_time, "Deactivation Time"),
    [PFCP_IE_CREATE_MAR] =
    {
      .name = "Create MAR",
      .length = sizeof(pfcp_create_mar_t),
      .size = ARRAY_LEN(pfcp_create_mar_group),
      .group = pfcp_create_mar_group,
    },
    [PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_1] =
    {
      .name = "Access Forwarding Action Information 1",
      .length = sizeof(pfcp_access_forwarding_action_information_t),
      .size = ARRAY_LEN(pfcp_access_forwarding_action_information_group),
      .group = pfcp_access_forwarding_action_information_group,
    },
    [PFCP_IE_ACCESS_FORWARDING_ACTION_INFORMATION_2] =
    {
      .name = "Access Forwarding Action Information 2",
      .length = sizeof(pfcp_access_forwarding_action_information_t),
      .size = ARRAY_LEN(pfcp_access_forwarding_action_information_group),
      .group = pfcp_access_forwarding_action_information_group,
    },
    [PFCP_IE_REMOVE_MAR] =
    {
      .name = "Remove MAR",
      .length = sizeof(pfcp_remove_mar_t),
      .size = ARRAY_LEN(pfcp_remove_mar_group),
      .group = pfcp_remove_mar_group,
    },
    [PFCP_IE_UPDATE_MAR] =
    {
      .name = "Update MAR",
      .length = sizeof(pfcp_update_mar_t),
      .size = ARRAY_LEN(pfcp_update_mar_group),
      .group = pfcp_update_mar_group,
    },
    SIMPLE_IE(PFCP_IE_MAR_ID, mar_id, "MAR ID"),
    SIMPLE_IE(PFCP_IE_STEERING_FUNCTIONALITY, steering_functionality, "Steering Functionality"),
    SIMPLE_IE(PFCP_IE_STEERING_MODE, steering_mode, "Steering Mode"),
    SIMPLE_IE(PFCP_IE_WEIGHT, weight, "Weight"),
    SIMPLE_IE(PFCP_IE_PRIORITY, priority, "Priority"),
    [PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1] =
    {
      .name = "Update Access Forwarding Action Information 1",
      .length = sizeof(pfcp_update_access_forwarding_action_information_t),
      .size = ARRAY_LEN(pfcp_update_access_forwarding_action_information_group),
      .group = pfcp_update_access_forwarding_action_information_group,
    },
    [PFCP_IE_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2] =
    {
      .name = "Update Access Forwarding Action Information 2",
      .length = sizeof(pfcp_update_access_forwarding_action_information_t),
      .size = ARRAY_LEN(pfcp_update_access_forwarding_action_information_group),
      .group = pfcp_update_access_forwarding_action_information_group,
    },
    SIMPLE_IE(PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY, ue_ip_address_pool_identity, "UE IP address Pool Identity"),
    SIMPLE_IE(PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS, alternative_smf_ip_address, "Alternative SMF IP Address"),
  };

static struct pfcp_ie_def vendor_tp_specs[] =
  {
   SIMPLE_IE(PFCP_IE_TP_PACKET_MEASUREMENT, tp_packet_measurement, "TP: Packet Measurement"),
   SIMPLE_IE_FREE(PFCP_IE_TP_BUILD_ID, tp_build_id, "TP: Build Identifier"),
   SIMPLE_IE(PFCP_IE_TP_NOW, tp_now, "TP: Now"),
   SIMPLE_IE(PFCP_IE_TP_START_TIME, tp_start_time, "TP: Start Time"),
   SIMPLE_IE(PFCP_IE_TP_END_TIME, tp_end_time, "TP: Start Time"),
  };

/**********************************************************/

u8 *
format_pfcp_ie (u8 * s, va_list * args)
{
  pfcp_ie_t *ie = va_arg (*args, pfcp_ie_t *);
  u16 type = clib_net_to_host_u16 (ie->type);

  if (type & 0x8000)
    {
      pfcp_ie_vendor_t *vie = (pfcp_ie_vendor_t *)ie;
      u16 vendor = clib_net_to_host_u16 (vie->vendor);

      type &= ~0x8000;

      if (vendor == VENDOR_TRAVELPING &&
	  type < ARRAY_LEN (vendor_tp_specs) && vendor_tp_specs[type].name)
	{
	  return format (s, "IE: %s (%d:%d), Length: %d.",
			 vendor_tp_specs[type].name, vendor, type,
			 clib_net_to_host_u16 (ie->length));
	}
      else
	return format (s, "IE: %d:%d, Length: %d.", vendor, type,
		       clib_net_to_host_u16 (ie->length));
    }

  if (type < ARRAY_LEN (tgpp_specs) && tgpp_specs[type].name)
    return format (s, "IE: %s (%d), Length: %d.",
		   tgpp_specs[type].name, type, clib_net_to_host_u16 (ie->length));
  else
    return format (s, "IE: %d, Length: %d.", type,
		   clib_net_to_host_u16 (ie->length));
}

/**********************************************************/


/* PFCP Methods */

static struct pfcp_group_ie_def pfcp_simple_response_group[] =
  {
    [PFCP_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_simple_response_t, response.cause)
    },
    [PFCP_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_simple_response_t, response.offending_ie)
    },
    [PFCP_RESPONSE_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_simple_response_t, response.recovery_time_stamp)
    },
  };

static struct pfcp_group_ie_def pfcp_heartbeat_request_group[] =
  {
    [HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_heartbeat_request_t, recovery_time_stamp)
    },
  };

static struct pfcp_group_ie_def pfcp_pfd_management_request_group[] =
  {
    [PFD_MANAGEMENT_REQUEST_APPLICATION_ID_PFDS] = {
      .type = PFCP_IE_APPLICATION_ID_PFDS,
      .is_array = true,
      .offset = offsetof(pfcp_pfd_management_request_t, application_id_pfds)
    },
  };

static struct pfcp_group_ie_def pfcp_association_setup_request_group[] =
  {
    [ASSOCIATION_SETUP_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_setup_request_t, request.node_id)
    },
    [ASSOCIATION_SETUP_REQUEST_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_association_setup_request_t, recovery_time_stamp)
    },
    [ASSOCIATION_SETUP_REQUEST_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_request_t, cp_function_features)
    },
    [ASSOCIATION_SETUP_REQUEST_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_request_t, up_function_features)
    },
    [ASSOCIATION_SETUP_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_request_t, user_plane_ip_resource_information)
    },
    [ASSOCIATION_SETUP_REQUEST_TP_BUILD_ID] = {
      .type = PFCP_IE_TP_BUILD_ID,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_association_setup_request_t, tp_build_id)
    },
    [ASSOCIATION_SETUP_REQUEST_UE_IP_ADDRESS_POOL_IDENTITY] = {
      .type = PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_request_t, ue_ip_address_pool_identity)
    },
    [ASSOCIATION_SETUP_REQUEST_ALTERNATIVE_SMF_IP_ADDRESS] = {
      .type = PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_request_t, alternative_smf_ip_address)
    },
  };

static struct pfcp_group_ie_def pfcp_association_setup_response_group[] =
  {
    [ASSOCIATION_SETUP_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_setup_response_t, response.node_id)
    },
    [ASSOCIATION_SETUP_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_association_setup_response_t, response.cause)
    },
    [ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_association_setup_response_t, recovery_time_stamp)
    },
    [ASSOCIATION_SETUP_RESPONSE_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_response_t, cp_function_features)
    },
    [ASSOCIATION_SETUP_RESPONSE_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_response_t, up_function_features)
    },
    [ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_response_t, user_plane_ip_resource_information)
    },
    [ASSOCIATION_SETUP_RESPONSE_TP_BUILD_ID] = {
      .type = PFCP_IE_TP_BUILD_ID,
      .vendor = VENDOR_TRAVELPING,
      .offset = offsetof(pfcp_association_setup_response_t, tp_build_id)
    },
    [ASSOCIATION_SETUP_RESPONSE_UE_IP_ADDRESS_POOL_IDENTITY] = {
      .type = PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_response_t, ue_ip_address_pool_identity)
    },
  };

static struct pfcp_group_ie_def pfcp_association_update_request_group[] =
  {
    [ASSOCIATION_UPDATE_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_update_request_t, request.node_id)
    },
    [ASSOCIATION_UPDATE_REQUEST_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_request_t, cp_function_features)
    },
    [ASSOCIATION_UPDATE_REQUEST_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_request_t, up_function_features)
    },
    [ASSOCIATION_UPDATE_REQUEST_PFCP_ASSOCIATION_RELEASE_REQUEST] = {
      .type = PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST,
      .offset = offsetof(pfcp_association_update_request_t, pfcp_association_release_request)
    },
    [ASSOCIATION_UPDATE_REQUEST_GRACEFUL_RELEASE_PERIOD] = {
      .type = PFCP_IE_GRACEFUL_RELEASE_PERIOD,
      .offset = offsetof(pfcp_association_update_request_t, graceful_release_period)
    },
    [ASSOCIATION_UPDATE_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_update_request_t, user_plane_ip_resource_information)
    },
    [ASSOCIATION_UPDATE_REQUEST_PFCPAUREQ_FLAGS] = {
      .type = PFCP_IE_PFCPAUREQ_FLAGS,
      .offset = offsetof(pfcp_association_update_request_t, pfcpaureq_flags)
    },
    [ASSOCIATION_UPDATE_REQUEST_UE_IP_ADDRESS_POOL_IDENTITY] = {
      .type = PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY,
      .is_array = true,
      .offset = offsetof(pfcp_association_update_request_t, ue_ip_address_pool_identity)
    },
    [ASSOCIATION_UPDATE_REQUEST_ALTERNATIVE_SMF_IP_ADDRESS] = {
      .type = PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS,
      .is_array = true,
      .offset = offsetof(pfcp_association_update_request_t, alternative_smf_ip_address)
    },
  };

static struct pfcp_group_ie_def pfcp_association_update_response_group[] =
  {
    [ASSOCIATION_UPDATE_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_update_response_t, response.node_id)
    },
    [ASSOCIATION_UPDATE_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_association_update_response_t, response.cause)
    },
    [ASSOCIATION_UPDATE_RESPONSE_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_response_t, cp_function_features)
    },
    [ASSOCIATION_UPDATE_RESPONSE_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_response_t, up_function_features)
    },
  };

static struct pfcp_group_ie_def pfcp_association_release_request_group[] =
  {
    [ASSOCIATION_RELEASE_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_release_request_t, request.node_id)
    },
  };

static struct pfcp_group_ie_def pfcp_node_report_request_group[] =
  {
    [NODE_REPORT_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_node_report_request_t, request.node_id)
    },
    [NODE_REPORT_REQUEST_NODE_REPORT_TYPE] = {
      .type = PFCP_IE_NODE_REPORT_TYPE,
      .offset = offsetof(pfcp_node_report_request_t, node_report_type)
    },
    [NODE_REPORT_REQUEST_USER_PLANE_PATH_FAILURE_REPORT] = {
      .type = PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT,
      .offset = offsetof(pfcp_node_report_request_t, user_plane_path_failure_report)
    },
  };

static struct pfcp_group_ie_def pfcp_session_set_deletion_request_group[] =
  {
    [SESSION_SET_DELETION_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_set_deletion_request_t, request.node_id)
    },
    [SESSION_SET_DELETION_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_set_deletion_request_t, fq_csid)
    },
  };

static struct pfcp_group_ie_def pfcp_session_establishment_request_group[] =
  {
    [SESSION_ESTABLISHMENT_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_establishment_request_t, request.node_id)
    },
    [SESSION_ESTABLISHMENT_REQUEST_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_establishment_request_t, f_seid)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_PDR] = {
      .type = PFCP_IE_CREATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_pdr)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_FAR] = {
      .type = PFCP_IE_CREATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_far)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_URR] = {
      .type = PFCP_IE_CREATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_urr)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_QER] = {
      .type = PFCP_IE_CREATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_qer)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_BAR] = {
      .type = PFCP_IE_CREATE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_bar)
    },
     [SESSION_ESTABLISHMENT_REQUEST_CREATE_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_CREATE_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_traffic_endpoint)
    },
    [SESSION_ESTABLISHMENT_REQUEST_PDN_TYPE] = {
      .type = PFCP_IE_PDN_TYPE,
      .offset = offsetof(pfcp_session_establishment_request_t, pdn_type)
    },
    [SESSION_ESTABLISHMENT_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, fq_csid)
    },
    [SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER] = {
      .type = PFCP_IE_USER_PLANE_INACTIVITY_TIMER,
      .offset = offsetof(pfcp_session_establishment_request_t, user_plane_inactivity_timer)
    },
    [SESSION_ESTABLISHMENT_REQUEST_USER_ID] = {
      .type = PFCP_IE_USER_ID,
      .offset = offsetof(pfcp_session_establishment_request_t, user_id)
    },
    [SESSION_ESTABLISHMENT_REQUEST_TRACE_INFORMATION] = {
      .type = PFCP_IE_TRACE_INFORMATION,
      .offset = offsetof(pfcp_session_establishment_request_t, trace_information)
    },
    [SESSION_ESTABLISHMENT_REQUEST_APN_DNN] = {
      .type = PFCP_IE_APN_DNN,
      .offset = offsetof(pfcp_session_establishment_request_t, apn_dnn)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_MAR] = {
      .type = PFCP_IE_CREATE_MAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_mar)
    },
  };

static struct pfcp_group_ie_def pfcp_session_establishment_response_group[] =
  {
    [SESSION_ESTABLISHMENT_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_establishment_response_t, response.node_id)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_establishment_response_t, response.cause)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_establishment_response_t, response.offending_ie)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_establishment_response_t, up_f_seid)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_CREATED_PDR] = {
      .type = PFCP_IE_CREATED_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_response_t, created_pdr)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_establishment_response_t, load_control_information)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_establishment_response_t, overload_control_information)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_response_t, fq_csid)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID] = {
      .type = PFCP_IE_FAILED_RULE_ID,
      .offset = offsetof(pfcp_session_establishment_response_t, failed_rule_id)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_CREATED_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_CREATED_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_response_t, created_traffic_endpoint)
    },
  };

static struct pfcp_group_ie_def pfcp_session_modification_request_group[] =
  {
    [SESSION_MODIFICATION_REQUEST_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_modification_request_t, f_seid)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_PDR] = {
      .type = PFCP_IE_REMOVE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_FAR] = {
      .type = PFCP_IE_REMOVE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_far)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_URR] = {
      .type = PFCP_IE_REMOVE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_urr)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_QER] = {
      .type = PFCP_IE_REMOVE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_qer)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_BAR] = {
      .type = PFCP_IE_REMOVE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_bar)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_REMOVE_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_traffic_endpoint)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_PDR] = {
      .type = PFCP_IE_CREATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_FAR] = {
      .type = PFCP_IE_CREATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_far)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_URR] = {
      .type = PFCP_IE_CREATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_urr)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_QER] = {
      .type = PFCP_IE_CREATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_qer)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_BAR] = {
      .type = PFCP_IE_CREATE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_bar)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_CREATE_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_traffic_endpoint)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_PDR] = {
      .type = PFCP_IE_UPDATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_FAR] = {
      .type = PFCP_IE_UPDATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_far)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_URR] = {
      .type = PFCP_IE_UPDATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_urr)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_QER] = {
      .type = PFCP_IE_UPDATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_qer)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_BAR] = {
      .type = PFCP_IE_UPDATE_BAR_REQUEST,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_bar)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_UPDATE_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_traffic_endpoint)
    },
    [SESSION_MODIFICATION_REQUEST_PFCPSMREQ_FLAGS] = {
      .type = PFCP_IE_PFCPSMREQ_FLAGS,
      .offset = offsetof(pfcp_session_modification_request_t, pfcpsmreq_flags)
    },
    [SESSION_MODIFICATION_REQUEST_QUERY_URR] = {
      .type = PFCP_IE_QUERY_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, query_urr)
    },
    [SESSION_MODIFICATION_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, fq_csid)
    },
    [SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER] = {
      .type = PFCP_IE_USER_PLANE_INACTIVITY_TIMER,
      .offset = offsetof(pfcp_session_modification_request_t, user_plane_inactivity_timer)
    },
    [SESSION_MODIFICATION_REQUEST_QUERY_URR_REFERENCE] = {
      .type = PFCP_IE_QUERY_URR_REFERENCE,
      .offset = offsetof(pfcp_session_modification_request_t, query_urr_reference)
    },
    [SESSION_MODIFICATION_REQUEST_TRACE_INFORMATION] = {
      .type = PFCP_IE_TRACE_INFORMATION,
      .offset = offsetof(pfcp_session_modification_request_t, trace_information)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_MAR] = {
      .type = PFCP_IE_REMOVE_MAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_mar)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_MAR] = {
      .type = PFCP_IE_UPDATE_MAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_mar)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_MAR] = {
      .type = PFCP_IE_CREATE_MAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_mar)
    },
  };

static struct pfcp_group_ie_def pfcp_session_modification_response_group[] =
  {
    [SESSION_MODIFICATION_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_modification_response_t, response.cause)
    },
    [SESSION_MODIFICATION_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_modification_response_t, response.offending_ie)
    },
    [SESSION_MODIFICATION_RESPONSE_CREATED_PDR] = {
      .type = PFCP_IE_CREATED_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_response_t, created_pdr)
    },
    [SESSION_MODIFICATION_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_modification_response_t, load_control_information)
    },
    [SESSION_MODIFICATION_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_modification_response_t, overload_control_information)
    },
    [SESSION_MODIFICATION_RESPONSE_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SMR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_response_t, usage_report)
    },
    [SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID] = {
      .type = PFCP_IE_FAILED_RULE_ID,
      .offset = offsetof(pfcp_session_modification_response_t, failed_rule_id)
    },
    [SESSION_MODIFICATION_RESPONSE_ADDITIONAL_USAGE_REPORTS_INFORMATION] = {
      .type = PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,
      .offset = offsetof(pfcp_session_modification_response_t, additional_usage_reports_information)
    },
    [SESSION_MODIFICATION_RESPONSE_CREATED_TRAFFIC_ENDPOINT] = {
      .type = PFCP_IE_CREATED_TRAFFIC_ENDPOINT,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_response_t, created_traffic_endpoint)
    },
  };

static struct pfcp_group_ie_def pfcp_session_deletion_response_group[] =
  {
    [SESSION_DELETION_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_deletion_response_t, response.cause)
    },
    [SESSION_DELETION_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_deletion_response_t, response.offending_ie)
    },
    [SESSION_DELETION_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_deletion_response_t, load_control_information)
    },
    [SESSION_DELETION_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_deletion_response_t, overload_control_information)
    },
    [SESSION_DELETION_RESPONSE_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_deletion_response_t, usage_report)
    },
  };

static struct pfcp_group_ie_def pfcp_session_report_request_group[] =
  {
    [SESSION_REPORT_REQUEST_REPORT_TYPE] = {
      .type = PFCP_IE_REPORT_TYPE,
      .offset = offsetof(pfcp_session_report_request_t, report_type)
    },
    [SESSION_REPORT_REQUEST_DOWNLINK_DATA_REPORT] = {
      .type = PFCP_IE_DOWNLINK_DATA_REPORT,
      .offset = offsetof(pfcp_session_report_request_t, downlink_data_report)
    },
    [SESSION_REPORT_REQUEST_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SRR,
      .is_array = true,
      .offset = offsetof(pfcp_session_report_request_t, usage_report)
    },
    [SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT] = {
      .type = PFCP_IE_ERROR_INDICATION_REPORT,
      .offset = offsetof(pfcp_session_report_request_t, error_indication_report)
    },
    [SESSION_REPORT_REQUEST_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_report_request_t, load_control_information)
    },
    [SESSION_REPORT_REQUEST_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_report_request_t, overload_control_information)
    },
    [SESSION_REPORT_REQUEST_ADDITIONAL_USAGE_REPORTS_INFORMATION] = {
      .type = PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,
      .offset = offsetof(pfcp_session_report_request_t, additional_usage_reports_information)
    },
    [SESSION_REPORT_REQUEST_PFCPSRREQ_FLAGS] = {
      .type = PFCP_IE_PFCPSRREQ_FLAGS,
      .offset = offsetof(pfcp_session_report_request_t, pfcpsrreq_flags)
    },
  };

static struct pfcp_group_ie_def pfcp_session_report_response_group[] =
  {
    [SESSION_REPORT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_report_response_t, response.cause)
    },
    [SESSION_REPORT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_report_response_t, response.offending_ie)
    },
    [SESSION_REPORT_RESPONSE_UPDATE_BAR] = {
      .type = PFCP_IE_UPDATE_BAR_RESPONSE,
      .is_array = true,
      .offset = offsetof(pfcp_session_report_response_t, update_bar)
    },
    [SESSION_REPORT_RESPONSE_PFCPSRRSP_FLAGS] = {
      .type = PFCP_IE_PFCPSRRSP_FLAGS,
      .offset = offsetof(pfcp_session_report_response_t, pfcpsrrsp_flags)
    },
    [SESSION_REPORT_RESPONSE_CP_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_report_response_t, cp_f_seid)
    },
    [SESSION_REPORT_RESPONSE_N4_u_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_session_report_response_t, n4_u_f_teid)
    },
  };


static struct pfcp_ie_def msg_specs[] =
  {
    [PFCP_HEARTBEAT_REQUEST] =
    {
      .length = sizeof(pfcp_heartbeat_request_t),
      .mandatory = BIT(HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP),
      .size = ARRAY_LEN(pfcp_heartbeat_request_group),
      .group = pfcp_heartbeat_request_group,
    },

    [PFCP_HEARTBEAT_RESPONSE] =
    {
      .length = sizeof(pfcp_simple_response_t),
      .mandatory = BIT(PFCP_RESPONSE_RECOVERY_TIME_STAMP),
      .size = ARRAY_LEN(pfcp_simple_response_group),
      .group = pfcp_simple_response_group,
    },

    [PFCP_PFD_MANAGEMENT_REQUEST] =
    {
      .length = sizeof(pfcp_pfd_management_request_t),
      .size = ARRAY_LEN(pfcp_pfd_management_request_group),
      .group = pfcp_pfd_management_request_group,
    },

    [PFCP_ASSOCIATION_SETUP_REQUEST] =
    {
      .length = sizeof(pfcp_association_setup_request_t),
      .mandatory = (BIT(ASSOCIATION_SETUP_REQUEST_NODE_ID) |
		    BIT(ASSOCIATION_SETUP_REQUEST_RECOVERY_TIME_STAMP)),
      .size = ARRAY_LEN(pfcp_association_setup_request_group),
      .group = pfcp_association_setup_request_group,
    },

    [PFCP_ASSOCIATION_SETUP_RESPONSE] =
    {
      .length = sizeof(pfcp_association_setup_response_t),
      .mandatory = (BIT(ASSOCIATION_SETUP_RESPONSE_NODE_ID) |
		    BIT(ASSOCIATION_SETUP_RESPONSE_CAUSE) |
		    BIT(ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP)),
      .size = ARRAY_LEN(pfcp_association_setup_response_group),
      .group = pfcp_association_setup_response_group,
    },

    [PFCP_ASSOCIATION_UPDATE_REQUEST] =
    {
      .length = sizeof(pfcp_association_update_request_t),
      .mandatory = BIT(ASSOCIATION_UPDATE_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_association_update_request_group),
      .group = pfcp_association_update_request_group,
    },

    [PFCP_ASSOCIATION_UPDATE_RESPONSE] =
    {
      .length = sizeof(pfcp_association_update_response_t),
      .mandatory = (BIT(ASSOCIATION_UPDATE_RESPONSE_NODE_ID) |
		    BIT(ASSOCIATION_UPDATE_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_association_update_response_group),
      .group = pfcp_association_update_response_group,
    },

    [PFCP_ASSOCIATION_RELEASE_REQUEST] =
    {
      .length = sizeof(pfcp_association_release_request_t),
      .mandatory = BIT(ASSOCIATION_RELEASE_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_association_release_request_group),
      .group = pfcp_association_release_request_group,
    },

    [PFCP_ASSOCIATION_RELEASE_RESPONSE] =
    {
      .length = sizeof(pfcp_simple_response_t),
      .mandatory = (BIT(PFCP_RESPONSE_NODE_ID) |
		    BIT(PFCP_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_simple_response_group),
      .group = pfcp_simple_response_group,
    },

    [PFCP_NODE_REPORT_REQUEST] =
    {
      .length = sizeof(pfcp_node_report_request_t),
      .mandatory = (BIT(NODE_REPORT_REQUEST_NODE_ID) |
		    BIT(NODE_REPORT_REQUEST_NODE_REPORT_TYPE)),
      .size = ARRAY_LEN(pfcp_node_report_request_group),
      .group = pfcp_node_report_request_group,
    },

    [PFCP_NODE_REPORT_RESPONSE] =
    {
      .length = sizeof(pfcp_simple_response_t),
      .mandatory = (BIT(PFCP_RESPONSE_NODE_ID) |
		    BIT(PFCP_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_simple_response_group),
      .group = pfcp_simple_response_group,
    },

    [PFCP_SESSION_SET_DELETION_REQUEST] =
    {
      .length = sizeof(pfcp_session_set_deletion_request_t),
      .mandatory = BIT(SESSION_SET_DELETION_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_session_set_deletion_request_group),
      .group = pfcp_session_set_deletion_request_group,
    },

    [PFCP_SESSION_SET_DELETION_RESPONSE] =
    {
      .length = sizeof(pfcp_simple_response_t),
      .mandatory = (BIT(PFCP_RESPONSE_NODE_ID) |
		    BIT(PFCP_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_simple_response_group),
      .group = pfcp_simple_response_group,
    },

    [PFCP_SESSION_ESTABLISHMENT_REQUEST] =
    {
      .length = sizeof(pfcp_session_establishment_request_t),
      .mandatory = (BIT(SESSION_ESTABLISHMENT_REQUEST_NODE_ID) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_F_SEID) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_CREATE_PDR) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_CREATE_FAR)),
      .size = ARRAY_LEN(pfcp_session_establishment_request_group),
      .group = pfcp_session_establishment_request_group,
    },

    [PFCP_SESSION_ESTABLISHMENT_RESPONSE] =
    {
      .length = sizeof(pfcp_session_establishment_response_t),
      .mandatory = (BIT(SESSION_ESTABLISHMENT_RESPONSE_NODE_ID) |
		    BIT(SESSION_ESTABLISHMENT_RESPONSE_CAUSE) |
		    BIT(SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID)),
      .size = ARRAY_LEN(pfcp_session_establishment_response_group),
      .group = pfcp_session_establishment_response_group,
    },

    [PFCP_SESSION_MODIFICATION_REQUEST] =

    {
    .length = sizeof(pfcp_session_modification_request_t),
    .size = ARRAY_LEN(pfcp_session_modification_request_group),
    .group = pfcp_session_modification_request_group,

    },

    [PFCP_SESSION_MODIFICATION_RESPONSE] =
    {
      .length = sizeof(pfcp_session_modification_response_t),
      .mandatory = BIT(SESSION_MODIFICATION_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_modification_response_group),
      .group = pfcp_session_modification_response_group,
    },

    [PFCP_SESSION_DELETION_REQUEST] =
    {
      .length = sizeof(pfcp_session_deletion_request_t),
    },

    [PFCP_SESSION_DELETION_RESPONSE] =
    {
      .length = sizeof(pfcp_session_deletion_response_t),
      .mandatory = BIT(SESSION_DELETION_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_deletion_response_group),
      .group = pfcp_session_deletion_response_group,
    },

    [PFCP_SESSION_REPORT_REQUEST] =
    {
      .length = sizeof(pfcp_session_report_request_t),
      .mandatory = BIT(SESSION_REPORT_REQUEST_REPORT_TYPE),
      .size = ARRAY_LEN(pfcp_session_report_request_group),
      .group = pfcp_session_report_request_group,
    },

    [PFCP_SESSION_REPORT_RESPONSE] =
    {
      .length = sizeof(pfcp_session_report_response_t),
      .mandatory = BIT(SESSION_REPORT_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_report_response_group),
      .group = pfcp_session_report_response_group,
    },
  };

/* *INDENT-ON* */

static const struct pfcp_group_ie_def *
get_ie_spec (const pfcp_ie_t * ie, const struct pfcp_ie_def *def)
{
  for (int i = 0; i < def->size; i++)
    if (def->group[i].type != 0 && def->group[i].type == ntohs (ie->type))
      return &def->group[i];

  return NULL;
}

static const struct pfcp_ie_def *
get_ie_def (const struct pfcp_group_ie_def *item)
{
  switch (item->vendor)
    {
    case 0:
      return &tgpp_specs[item->type];

    case VENDOR_TRAVELPING:
      return &vendor_tp_specs[item->type];
    }

  return NULL;
}

static int decode_group (u8 * p, int len, const struct pfcp_ie_def *grp_def,
			 struct pfcp_group *grp, pfcp_offending_ie_t ** err);

static int
decode_ie (const struct pfcp_ie_def *def, u8 * ie, u16 length, void *p,
	   pfcp_offending_ie_t ** err)
{
  int r;

  if (def->size != 0)
    return decode_group (ie, length, def, (struct pfcp_group *) p, err);
  else
    {
      if ((r = def->decode (ie, length, p)) == 0)
	pfcp_debug ("PFCP: %s: %U.", def->name, def->format, p);

      return r;
    }
}

static int
decode_vector_ie (const struct pfcp_ie_def *def, u8 * ie, u16 length, void *p,
		  pfcp_offending_ie_t ** err)
{
  u8 **v = (u8 **) p;
  uword vl;
  int r;

  /*
   * black magic to expand a vector without having know the element type...
   */
  vl = vec_len (*v);
  *v = _vec_resize (*v, 1, (vl + 1) * def->length, 0, 0);
  memset (*v + (vl * def->length), 0, def->length);
  _vec_len (*v) = vl;

  if ((r = decode_ie (def, ie, length, *v + (vl * def->length), err)) == 0)
    _vec_len (*v)++;

  return r;
}

static int
decode_group (u8 * p, int len, const struct pfcp_ie_def *grp_def,
	      struct pfcp_group *grp, pfcp_offending_ie_t ** err)
{
  int r = 0, pos = 0;

  while (r == 0 && pos < len)
    {
      pfcp_ie_t *ie = (pfcp_ie_t *) & p[pos];
      const struct pfcp_group_ie_def *item;
      const struct pfcp_ie_def *ie_def;
      u16 length = ntohs (ie->length);
      i16 type = ntohs (ie->type);

      pfcp_debug ("%U", format_pfcp_ie, ie);

      pos += 4;
      if (pos + length > len)
	return PFCP_CAUSE_INVALID_LENGTH;

      item = get_ie_spec (ie, grp_def);

      if (!item)
	{
	  vec_add1 (grp->ies, ie);
	  goto next;
	}

      int id = item - grp_def->group;

      if (type & 0x8000)
	{
	  pfcp_ie_vendor_t *vie = (pfcp_ie_vendor_t *) ie;
	  u16 vendor = ntohs (vie->vendor);

	  pos += 2;
	  length -= 2;
	  type &= ~0x8000;

	  switch (vendor)
	    {
	    case VENDOR_TRAVELPING:
	      ie_def = &vendor_tp_specs[type];
	      break;
	    default:
	      vec_add1 (grp->ies, ie);
	      goto next;
	    }
	}
      else
	{
	  ie_def = &tgpp_specs[type];
	}

      u8 *v = ((u8 *) grp) + item->offset;

      if (item->is_array)
	r = decode_vector_ie (ie_def, p + pos, length, v, err);
      else
	{
	  if (ISSET_BIT (grp->fields, id))
	    /* duplicate IE */
	    vec_add1 (grp->ies, ie);
	  else
	    r = decode_ie (ie_def, p + pos, length, v, err);
	}

      if (r == 0)
	SET_BIT (grp->fields, id);

    next:
      pos += length;
    }

  if ((grp->fields & grp_def->mandatory) != grp_def->mandatory)
    {
      u32 missing = ~grp->fields & grp_def->mandatory;

      pfcp_debug
	("Mandatory IE Missing: expected: %08x, got: %08x, Missing: %08x",
	 grp_def->mandatory, (grp->fields & grp_def->mandatory), missing);

      for (int i = 0; missing; i++, missing >>= 1)
	{
	  if (!(missing & 1))
	    continue;

#if CLIB_DEBUG > 1
	  const struct pfcp_ie_def *ie_def = get_ie_def (&grp_def->group[i]);
#endif
	  pfcp_debug ("Missing IE Type: %s, %u", ie_def->name,
		      grp_def->group[i].type);
	  vec_add1 (*err, grp_def->group[i].type);
	}

      return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

  return r;
}

int
pfcp_decode_msg (u16 type, u8 * p, int len, struct pfcp_group *grp,
		 pfcp_offending_ie_t ** err)
{
  assert (type < ARRAY_LEN (msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  return decode_group (p, len, &msg_specs[type], grp, err);
}

static int encode_group (const struct pfcp_ie_def *def,
			 struct pfcp_group *grp, u8 ** vec);

static int
encode_ie (const struct pfcp_group_ie_def *item,
	   const struct pfcp_ie_def *def, u8 * v, u8 ** vec)
{
  int hdr = _vec_len (*vec);
  int r = 0;

  if (item->vendor == 0)
    {
      set_ie_hdr_type (*vec, item->type, hdr);
      _vec_len (*vec) += sizeof (pfcp_ie_t);
    }
  else
    {
      set_ie_vendor_hdr_type (*vec, 0x8000 | item->type, item->vendor, hdr);
      set_ie_vendor_hdr_vendor (*vec, item->vendor, hdr);
      _vec_len (*vec) += sizeof (pfcp_ie_vendor_t);
    }

  if (def->size != 0)
    r = encode_group (def, (struct pfcp_group *) v, vec);
  else
    {
      pfcp_debug ("PFCP: %s: %U.", def->name, def->format, v);
      r = def->encode (v, vec);
    }

  if (r == 0)
    finalize_ie (*vec, hdr, _vec_len (*vec));
  else
    _vec_len (*vec) = hdr;

  return r;
}

static int
encode_vector_ie (const struct pfcp_group_ie_def *item,
		  const struct pfcp_ie_def *def, u8 * v, u8 ** vec)
{
  u8 *end;
  int r = 0;

  if (!*(u8 **) v)
    return 0;

  end = *(u8 **) v + _vec_len (*(u8 **) v) * def->length;
  for (u8 * p = *(u8 **) v; p < end; p += def->length)
    {
      if ((r = encode_ie (item, def, p, vec)) != 0)
	break;
    }

  return r;
}

static int
encode_group (const struct pfcp_ie_def *def, struct pfcp_group *grp,
	      u8 ** vec)
{
  int r = 0;

  for (int i = 0; i < def->size; i++)
    {
      const struct pfcp_group_ie_def *item = &def->group[i];
      const struct pfcp_ie_def *ie_def;
      u8 *v = ((u8 *) grp) + item->offset;

      if (item->type == 0)
	continue;

      if (!ISSET_BIT (grp->fields, i))
	continue;

      ie_def = get_ie_def (item);
      if (!ie_def)
	continue;

      if (item->is_array)
	r = encode_vector_ie (item, ie_def, v, vec);
      else
	r = encode_ie (item, ie_def, v, vec);

      if (r != 0)
	break;
    }

  return r;
}

int
pfcp_encode_msg (u16 type, struct pfcp_group *grp, u8 ** vec)
{
  assert (type < ARRAY_LEN (msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  return encode_group (&msg_specs[type], grp, vec);
}

static void free_group (const struct pfcp_ie_def *def,
			struct pfcp_group *grp);

static void
free_ie (const struct pfcp_group_ie_def *item,
	 const struct pfcp_ie_def *def, u8 * v)
{
  if (def->size != 0)
    free_group (def, (struct pfcp_group *) v);
  else if (def->free)
    def->free (v);
}

static void
free_vector_ie (const struct pfcp_group_ie_def *item,
		const struct pfcp_ie_def *def, u8 * v)
{
  for (u8 * i = *(u8 **) v; i < vec_end (*(u8 **) v); i += def->length)
    free_ie (item, def, i);
  vec_free (*(u8 **) v);
}

static void
free_group (const struct pfcp_ie_def *def, struct pfcp_group *grp)
{
  for (int i = 0; i < def->size; i++)
    {
      const struct pfcp_group_ie_def *item = &def->group[i];
      const struct pfcp_ie_def *ie_def = get_ie_def (item);
      u8 *v = ((u8 *) grp) + item->offset;

      if (item->type == 0)
	continue;

      if (!ISSET_BIT (grp->fields, i))
	continue;

      if (item->is_array)
	free_vector_ie (item, ie_def, v);
      else
	free_ie (item, ie_def, v);
    }
}

void
pfcp_free_msg (u16 type, struct pfcp_group *grp)
{
  assert (type < ARRAY_LEN (msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  free_group (&msg_specs[type], grp);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
