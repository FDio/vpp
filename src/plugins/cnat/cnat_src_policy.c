/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <cnat/cnat_src_policy.h>
#include <cnat/cnat_inline.h>

#include <cnat/cnat_session.h>
#include <cnat/cnat_translation.h>

cnat_src_policy_main_t cnat_src_policy_main;

void
cnat_register_vip_src_policy (cnat_vip_source_policy_t fp)
{
  cnat_src_policy_main.vip_policy = fp;
}

cnat_source_policy_errors_t
cnat_vip_default_source_policy (vlib_main_t * vm,
				vlib_buffer_t * b,
				cnat_session_t * session,
				u32 * rsession_flags,
				const cnat_translation_t * ct,
				cnat_node_ctx_t * ctx)
{
  ip_protocol_t iproto;
  udp_header_t *udp0;
  ip4_header_t *ip4;
  ip6_header_t *ip6;

  if (AF_IP4 == ctx->af)
    {
      ip4 = vlib_buffer_get_current (b);
      iproto = ip4->protocol;
      udp0 = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      ip6 = vlib_buffer_get_current (b);
      iproto = ip6->protocol;
      udp0 = (udp_header_t *) (ip6 + 1);
    }

  int rv = 0;
  if (!session->value.cs_port[VLIB_RX])
    {
      u16 sport;
      sport = udp0->src_port;
      /* Allocate a port only if asked and if we actually sNATed */
      if ((ct->flags & CNAT_TR_FLAG_ALLOCATE_PORT) &&
	  (*rsession_flags & CNAT_SESSION_FLAG_HAS_SNAT))
	{
	  sport = 0;		/* force allocation */
	  session->value.flags |= CNAT_SESSION_FLAG_ALLOC_PORT;
	  rv = cnat_allocate_port (&sport, iproto);
	  if (rv)
	    return CNAT_SOURCE_ERROR_EXHAUSTED_PORTS;
	}

      session->value.cs_port[VLIB_RX] = sport;
    }
  return 0;
}

always_inline cnat_src_port_allocator_t *
cnat_get_src_port_allocator (ip_protocol_t iproto)
{
  cnat_src_policy_main_t *cspm = &cnat_src_policy_main;
  switch (iproto)
    {
    case IP_PROTOCOL_TCP:
      return &cspm->src_ports[CNAT_SPORT_PROTO_TCP];
    case IP_PROTOCOL_UDP:
      return &cspm->src_ports[CNAT_SPORT_PROTO_UDP];
    case IP_PROTOCOL_ICMP:
      return &cspm->src_ports[CNAT_SPORT_PROTO_ICMP];
    case IP_PROTOCOL_ICMP6:
      return &cspm->src_ports[CNAT_SPORT_PROTO_ICMP6];
    default:
      return 0;
    }
}

void
cnat_free_port (u16 port, ip_protocol_t iproto)
{
  cnat_src_port_allocator_t *ca;
  ca = cnat_get_src_port_allocator (iproto);
  if (!ca)
    return;
  clib_spinlock_lock (&ca->lock);
  clib_bitmap_set_no_check (ca->bmap, port, 0);
  clib_spinlock_unlock (&ca->lock);
}

int
cnat_allocate_port (u16 * port, ip_protocol_t iproto)
{
  *port = clib_net_to_host_u16 (*port);
  if (*port == 0)
    *port = MIN_SRC_PORT;
  cnat_src_port_allocator_t *ca;
  ca = cnat_get_src_port_allocator (iproto);
  if (!ca)
    return -1;
  clib_spinlock_lock (&ca->lock);
  if (clib_bitmap_get_no_check (ca->bmap, *port))
    {
      *port = clib_bitmap_next_clear (ca->bmap, *port);
      if (PREDICT_FALSE (*port >= UINT16_MAX))
	*port = clib_bitmap_next_clear (ca->bmap, MIN_SRC_PORT);
      if (PREDICT_FALSE (*port >= UINT16_MAX))
	{
	  clib_spinlock_unlock (&ca->lock);
	  return -1;
	}
    }
  clib_bitmap_set_no_check (ca->bmap, *port, 1);
  *port = clib_host_to_net_u16 (*port);
  clib_spinlock_unlock (&ca->lock);
  return 0;
}

static clib_error_t *
cnat_src_policy_init (vlib_main_t * vm)
{
  cnat_src_policy_main_t *cspm = &cnat_src_policy_main;
  cspm->vip_policy = cnat_vip_default_source_policy;
  cspm->default_policy = cnat_vip_default_source_policy;

  vec_validate (cspm->src_ports, CNAT_N_SPORT_PROTO);
  for (int i = 0; i < CNAT_N_SPORT_PROTO; i++)
    {
      clib_spinlock_init (&cspm->src_ports[i].lock);
      clib_bitmap_validate (cspm->src_ports[i].bmap, UINT16_MAX);
    }
  /* Inject cleanup callback */
  cnat_free_port_cb = cnat_free_port;
  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_src_policy_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
