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

#ifndef __LISP_GPE_TENANT_H__
#define __LISP_GPE_TENANT_H__

#include <vnet/lisp-gpe/lisp_gpe.h>

/**
 * Refernece counting lock types on the tenant.
 * When all of these counters drop to zero, we no longer need the tenant.
 */
typedef enum lisp_gpe_tenant_lock_t_
{
  LISP_GPE_TENANT_LOCK_L2_IFACE,
  LISP_GPE_TENANT_LOCK_L3_IFACE,
  LISP_GPE_TENANT_LOCK_NUM,
} lisp_gpe_tenant_lock_t;

/**
 * @brief Representation of the data associated with a LISP overlay tenant
 *
 * This object exists to manage the shared resources of the L2 and L3 interface
 * of a given tenant.
 */
typedef struct lisp_gpe_tenant_t_
{
  /**
   * The VNI is the identifier of the tenant
   */
  u32 lt_vni;

  /**
   * The tenant can have both L2 and L3 services enabled.
   */
  u32 lt_table_id;
  u32 lt_bd_id;

  /**
   * The number of locks on the tenant's L3 interface.
   */
  u32 lt_locks[LISP_GPE_TENANT_LOCK_NUM];

  /**
   * The L3 SW interface index
   */
  u32 lt_l3_sw_if_index;

  /**
   * The L2 SW interface index
   */
  u32 lt_l2_sw_if_index;

} lisp_gpe_tenant_t;

extern u32 lisp_gpe_tenant_find_or_create (u32 vni);

extern u32 lisp_gpe_tenant_l3_iface_add_or_lock (u32 vni, u32 vrf,
						 u8 with_default_route);
extern void lisp_gpe_tenant_l3_iface_unlock (u32 vni);

extern u32 lisp_gpe_tenant_l2_iface_add_or_lock (u32 vni, u32 vrf);
extern void lisp_gpe_tenant_l2_iface_unlock (u32 vni);

extern const lisp_gpe_tenant_t *lisp_gpe_tenant_get (u32 index);

extern void lisp_gpe_tenant_flush (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
