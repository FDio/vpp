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

#ifndef __CALICO_VIP_H__
#define __CALICO_VIP_H__

#include <calico/calico_types.h>
#include <calico/calico_translation.h>

/**
 * A VIP represents a virtual IP address.
 * Translations are bsed on virtual endpoints (i.e. address and port)
 * so many translation refer to one VIP.
 * VIP are created when the first translation needs one and delete
 * when the last translation is gone.
 * It it the VIP object the is inserted into the FIB for the prefix
 * matching VIP/32.
 */
typedef struct calico_vip_t_
{
  /**
   * The VIP
   */
  ip_address_t cvip_ip;

  /**
   * DB of translations refering to the VIP.
   * translations key'd on port & proto
   */
  uword *cvip_translations;

  /**
   * the DPO inserted into the FIB
   */
  dpo_id_t cvip_dpo;

  /**
   * The FIB entry sourced
   */
  fib_node_index_t cvip_fei;
} calico_vip_t;


/**
 * A DPO type registered for VIP in the FIB graph
 */
extern dpo_type_t calico_vip_dpo;

extern u8 *format_calico_vip (u8 * s, va_list * args);

/**
 * Remove a translation that references this VIP
 */
extern void calico_vip_remove_translation (index_t cvipi,
					   u16 port, ip_protocol_t proto);

/**
 * Add a translation that references this VIP
 */
extern void calico_vip_add_translation (index_t cvipi,
					u16 port,
					ip_protocol_t proto, index_t cti);
/**
 * Add a new VIP object for an ip address
 */
extern index_t calico_vip_add (const ip_address_t * ip);

/*
 * Data plane functions
 */
extern calico_vip_t *calico_vip_pool;

static_always_inline calico_vip_t *
calico_vip_get (index_t i)
{
  return (pool_elt_at_index (calico_vip_pool, i));
}

static_always_inline calico_translation_t *
calico_vip_find_translation (index_t cvipi, u16 port, ip_protocol_t proto)
{
  const calico_vip_t *cvip;
  uword *p;
  u32 key;

  cvip = calico_vip_get (cvipi);

  key = proto;
  key = (key << 16) | port;

  p = hash_get (cvip->cvip_translations, key);

  if (p)
    return (pool_elt_at_index (calico_translation_pool, p[0]));

  return (NULL);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
