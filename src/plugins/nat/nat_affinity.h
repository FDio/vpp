/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT plugin client-IP based session affinity for load-balancing
 */

#ifndef __included_nat_affinity_h__
#define __included_nat_affinity_h__

#include <vnet/ip/ip.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/dlist.h>

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t service_addr;
      ip4_address_t client_addr;
      /* align by making this 4 octets even though its a 1 octet field */
      u32 proto;
      /* align by making this 4 octets even though its a 2 octets field */
      u32 service_port;
    };
    u64 as_u64[2];
  };
} nat_affinity_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  nat_affinity_key_t key;
  u32 sticky_time;
  u32 ref_cnt;
  u32 per_service_index;
  u8 backend_index;
  f64 expire;
}) nat_affinity_t;
/* *INDENT-ON* */

typedef struct
{
  nat_affinity_t *affinity_pool;
  clib_bihash_16_8_t affinity_hash;
  clib_spinlock_t affinity_lock;
  dlist_elt_t *list_pool;
  vlib_main_t *vlib_main;
} nat_affinity_main_t;

extern nat_affinity_main_t nat_affinity_main;

/**
 * @brief Get new affinity per service list head index.
 *
 * @returns new affinity per service list head index.
 */
u32 nat_affinity_get_per_service_list_head_index (void);

/**
 * @brief Flush all service affinity data.
 *
 * @param affinity_per_service_list_head_index Per sevice list head index.
 */
void nat_affinity_flush_service (u32 affinity_per_service_list_head_index);

/**
 * @brief Initialize NAT client-IP based affinity.
 *
 * @param vm vlib main.
 *
 * @return error code.
 */
clib_error_t *nat_affinity_init (vlib_main_t * vm);

/**
 * @brief Find service backend index for client-IP and take a reference
 *  counting lock.
 *
 * @param client_addr Client IP address.
 * @param service_addr Service IP address.
 * @param proto IP protocol number.
 * @param service_port Service L4 port number.
 * @param backend_index Service backend index for client-IP if found.
 *
 * @return 0 on success, non-zero value otherwise.
 */
int nat_affinity_find_and_lock (ip4_address_t client_addr,
				ip4_address_t service_addr, u8 proto,
				u16 service_port, u8 * backend_index);

/**
 * @brief Create affinity record and take reference counting lock.
 * @param client_addr Client IP address.
 * @param service_addr Service IP address.
 * @param proto IP protocol number.
 * @param service_port Service L4 port number.
 * @param backend_index Service backend index for client-IP.
 * @param sticky_time Affinity sticky time in seconds.
 * @param affinity_per_service_list_head_index Per sevice list head index.
 *
 * @return 0 on success, non-zero value otherwise.
 */
int nat_affinity_create_and_lock (ip4_address_t client_addr,
				  ip4_address_t service_addr, u8 proto,
				  u16 service_port, u8 backend_index,
				  u32 sticky_time,
				  u32 affinity_per_service_list_head_index);
/**
 * @brief Release a reference counting lock for affinity.
 *
 * @param client_addr Client IP address.
 * @param service_addr Service IP address.
 * @param proto IP protocol number.
 */
void nat_affinity_unlock (ip4_address_t client_addr,
			  ip4_address_t service_addr, u8 proto,
			  u16 service_port);

#endif /* __included_nat_affinity_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
