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

#include <vnet/lisp-gpe/lisp_gpe_tenant.h>

/**
 * The pool of all tenants
 */
static lisp_gpe_tenant_t *lisp_gpe_tenant_pool;

/**
 * The hash table of all tenants: key:{VNI}.
 */
uword *lisp_gpe_tenant_db;

static lisp_gpe_tenant_t *
lisp_gpe_tenant_find (u32 vni)
{
  uword *p;

  p = hash_get (lisp_gpe_tenant_db, vni);

  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (lisp_gpe_tenant_pool, p[0]));
}

static lisp_gpe_tenant_t *
lisp_gpe_tenant_find_or_create_i (u32 vni)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find (vni);

  if (NULL == lt)
    {
      pool_get (lisp_gpe_tenant_pool, lt);
      memset (lt, 0, sizeof (*lt));

      lt->lt_vni = vni;
      lt->lt_table_id = ~0;
      lt->lt_bd_id = ~0;

      hash_set (lisp_gpe_tenant_db, vni, lt - lisp_gpe_tenant_pool);
    }

  return (lt);
}

/**
 * @brief Find or create a tenant for the given VNI
 */
u32
lisp_gpe_tenant_find_or_create (u32 vni)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find (vni);

  if (NULL == lt)
    {
      lt = lisp_gpe_tenant_find_or_create_i (vni);
    }

  return (lt - lisp_gpe_tenant_pool);
}

/**
 * @brief If there are no more locks/users of te tenant, then delete it
 */
static void
lisp_gpe_tenant_delete_if_empty (lisp_gpe_tenant_t * lt)
{
  int i;

  for (i = 0; i < LISP_GPE_TENANT_LOCK_NUM; i++)
    {
      if (lt->lt_locks[i])
	return;
    }

  hash_unset (lisp_gpe_tenant_db, lt->lt_vni);
  pool_put (lisp_gpe_tenant_pool, lt);
}

/**
 * @brief Add/create and lock a new or find and lock the existing L3
 * interface for the tenant
 *
 * @paran vni The tenant's VNI
 * @param table_id the Tenant's L3 table ID.
 * @param with_default_route Install default route for the interface
 *
 * @return the SW IF index of the L3 interface
 */
u32
lisp_gpe_tenant_l3_iface_add_or_lock (u32 vni, u32 table_id,
				      u8 with_default_route)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find_or_create_i (vni);

  if (~0 == lt->lt_table_id)
    lt->lt_table_id = table_id;

  ASSERT (lt->lt_table_id == table_id);

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L3_IFACE])
    {
      /* create the l3 interface since there are currently no users of it */
      lt->lt_l3_sw_if_index =
	lisp_gpe_add_l3_iface (&lisp_gpe_main, vni, table_id,
			       with_default_route);
    }

  lt->lt_locks[LISP_GPE_TENANT_LOCK_L3_IFACE]++;

  return (lt->lt_l3_sw_if_index);
}

/**
 * @brief Release the lock held on the tenant's L3 interface
 */
void
lisp_gpe_tenant_l3_iface_unlock (u32 vni)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find (vni);

  if (NULL == lt)
    {
      clib_warning ("No tenant for VNI %d", vni);
      return;
    }

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L3_IFACE])
    {
      clib_warning ("No L3 interface for tenant VNI %d", vni);
      return;
    }

  lt->lt_locks[LISP_GPE_TENANT_LOCK_L3_IFACE]--;

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L3_IFACE])
    {
      /* the last user has gone, so delete the l3 interface */
      lisp_gpe_del_l3_iface (&lisp_gpe_main, vni, lt->lt_table_id);
    }

  /*
   * If there are no more locks on any tenant managed resource, then
   * this tenant is toast.
   */
  lisp_gpe_tenant_delete_if_empty (lt);
}

/**
 * @brief Add/create and lock a new or find and lock the existing L2
 * interface for the tenant
 *
 * @paran vni The tenant's VNI
 * @param table_id the Tenant's L2 Bridge Domain ID.
 *
 * @return the SW IF index of the L2 interface
 */
u32
lisp_gpe_tenant_l2_iface_add_or_lock (u32 vni, u32 bd_id)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find_or_create_i (vni);

  if (NULL == lt)
    {
      clib_warning ("No tenant for VNI %d", vni);
      return ~0;
    }

  if (~0 == lt->lt_bd_id)
    lt->lt_bd_id = bd_id;

  ASSERT (lt->lt_bd_id == bd_id);

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L2_IFACE])
    {
      /* create the l2 interface since there are currently no users of it */
      lt->lt_l2_sw_if_index =
	lisp_gpe_add_l2_iface (&lisp_gpe_main, vni, bd_id);
    }

  lt->lt_locks[LISP_GPE_TENANT_LOCK_L2_IFACE]++;

  return (lt->lt_l2_sw_if_index);
}

/**
 * @brief Release the lock held on the tenant's L3 interface
 */
void
lisp_gpe_tenant_l2_iface_unlock (u32 vni)
{
  lisp_gpe_tenant_t *lt;

  lt = lisp_gpe_tenant_find (vni);

  if (NULL == lt)
    {
      clib_warning ("No tenant for VNI %d", vni);
      return;
    }

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L2_IFACE])
    {
      clib_warning ("No L2 interface for tenant VNI %d", vni);
      return;
    }

  lt->lt_locks[LISP_GPE_TENANT_LOCK_L2_IFACE]--;

  if (0 == lt->lt_locks[LISP_GPE_TENANT_LOCK_L2_IFACE])
    {
      /* the last user has gone, so delete the l2 interface */
      lisp_gpe_del_l2_iface (&lisp_gpe_main, vni, lt->lt_bd_id);
    }

  /*
   * If there are no more locks on any tenant managed resource, then
   * this tenant is toast.
   */
  lisp_gpe_tenant_delete_if_empty (lt);
}

/**
 * @brief get a const pointer to the tenant object
 */
const lisp_gpe_tenant_t *
lisp_gpe_tenant_get (u32 index)
{
  return (pool_elt_at_index (lisp_gpe_tenant_pool, index));
}

/**
 * @brief Flush/delete ALL the tenants
 */
void
lisp_gpe_tenant_flush (void)
{
  lisp_gpe_tenant_t *lt;

  /* *INDENT-OFF* */
  pool_foreach(lt, lisp_gpe_tenant_pool,
  ({
    lisp_gpe_tenant_l2_iface_unlock(lt->lt_vni);
    lisp_gpe_tenant_l3_iface_unlock(lt->lt_vni);
  }));
  /* *INDENT-ON* */
}

/**
 * @brif Show/display one tenant
 */
static u8 *
format_lisp_gpe_tenant (u8 * s, va_list * ap)
{
  const lisp_gpe_tenant_t *lt = va_arg (*ap, lisp_gpe_tenant_t *);

  s = format (s, "VNI:%d ", lt->lt_vni);

  if (lt->lt_table_id != ~0)
    {
      s = format (s, "VRF:%d ", lt->lt_table_id);
      s = format (s, "L3-SW-IF:%d ", lt->lt_l3_sw_if_index);
    }

  if (lt->lt_bd_id != ~0)
    {
      s = format (s, "BD-ID:%d ", lt->lt_bd_id);
      s = format (s, "L2-SW-IF:%d ", lt->lt_l2_sw_if_index);
    }

  return (s);
}

/**
 * @brief CLI command to show LISP-GPE tenant.
 */
static clib_error_t *
lisp_gpe_tenant_show (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_gpe_tenant_t *lt;

  /* *INDENT-OFF* */
  pool_foreach (lt, lisp_gpe_tenant_pool,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_tenant, lt);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_tenant_command) = {
  .path = "show gpe tenant",
  .short_help = "show gpe tenant",
  .function = lisp_gpe_tenant_show,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
