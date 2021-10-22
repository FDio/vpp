/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
cnat_vip_default_source_policy (ip_protocol_t iproto, u16 *sport)
{
  int rv = 0;
  {
    /* Allocate a port only if asked and if we actually sNATed */
    *sport = 0; /* force allocation */
    rv = cnat_allocate_port (sport, iproto);
    if (rv)
      return CNAT_SOURCE_ERROR_EXHAUSTED_PORTS;
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
