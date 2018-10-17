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
/**
 * @file
 * @brief LISP sub-interfaces.
 *
 */
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/lisp-gpe/lisp_gpe_sub_interface.h>
#include <vnet/fib/fib_table.h>
#include <vnet/interface.h>

/**
 * @brief Pool of all l3-sub-interfaces
 */
static lisp_gpe_sub_interface_t *lisp_gpe_sub_interface_pool;

/**
 * A DB of all LISP L3 sub-interfaces. The key is:{VNI,l-RLOC}
 */
static uword *lisp_gpe_sub_interfaces;

/**
 * A DB of all VNET L3 sub-interfaces. The key is:{VNI,l-RLOC}
 * Used in the data-plane for interface lookup on decap.
 */
uword *lisp_gpe_sub_interfaces_sw_if_index;

/**
 * The next available sub-interface ID. FIXME
 */
static u32 lisp_gpe_sub_interface_id;


static index_t
lisp_gpe_sub_interface_db_find (const ip_address_t * lrloc, u32 vni)
{
  uword *p;

  lisp_gpe_sub_interface_key_t key;

  clib_memset (&key, 0, sizeof (key));
  ip_address_copy (&key.local_rloc, lrloc);
  key.vni = vni;
  p = hash_get_mem (lisp_gpe_sub_interfaces, &key);

  if (NULL == p)
    return (INDEX_INVALID);
  else
    return (p[0]);
}

static void
lisp_gpe_sub_interface_db_insert (const lisp_gpe_sub_interface_t * l3s)
{
  hash_set_mem (lisp_gpe_sub_interfaces,
		l3s->key, l3s - lisp_gpe_sub_interface_pool);
  hash_set_mem (lisp_gpe_sub_interfaces_sw_if_index,
		l3s->key, l3s->sw_if_index);
}

static void
lisp_gpe_sub_interface_db_remove (const lisp_gpe_sub_interface_t * l3s)
{
  hash_unset_mem (lisp_gpe_sub_interfaces, l3s->key);
  hash_unset_mem (lisp_gpe_sub_interfaces_sw_if_index, l3s->key);
}

lisp_gpe_sub_interface_t *
lisp_gpe_sub_interface_get_i (index_t l3si)
{
  return (pool_elt_at_index (lisp_gpe_sub_interface_pool, l3si));
}

static void
lisp_gpe_sub_interface_set_table (u32 sw_if_index, u32 table_id)
{
  fib_node_index_t fib_index;

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, table_id,
						 FIB_SOURCE_LISP);
  ASSERT (FIB_NODE_INDEX_INVALID != fib_index);

  vec_validate (ip4_main.fib_index_by_sw_if_index, sw_if_index);
  ip4_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, table_id,
						 FIB_SOURCE_LISP);
  ASSERT (FIB_NODE_INDEX_INVALID != fib_index);

  vec_validate (ip6_main.fib_index_by_sw_if_index, sw_if_index);
  ip6_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
}

static void
lisp_gpe_sub_interface_unset_table (u32 sw_if_index, u32 table_id)
{
  fib_table_unlock (ip4_main.fib_index_by_sw_if_index[sw_if_index],
		    FIB_PROTOCOL_IP4, FIB_SOURCE_LISP);
  ip4_main.fib_index_by_sw_if_index[sw_if_index] = 0;
  ip4_sw_interface_enable_disable (sw_if_index, 0);

  fib_table_unlock (ip6_main.fib_index_by_sw_if_index[sw_if_index],
		    FIB_PROTOCOL_IP6, FIB_SOURCE_LISP);
  ip6_main.fib_index_by_sw_if_index[sw_if_index] = 0;
  ip6_sw_interface_enable_disable (sw_if_index, 0);
}

index_t
lisp_gpe_sub_interface_find_or_create_and_lock (const ip_address_t * lrloc,
						u32 overlay_table_id, u32 vni)
{
  lisp_gpe_sub_interface_t *l3s;
  index_t l3si;

  l3si = lisp_gpe_sub_interface_db_find (lrloc, vni);

  if (INDEX_INVALID == l3si)
    {
      u32 main_sw_if_index, sub_sw_if_index;

      /*
       * find the main interface from the VNI
       */
      main_sw_if_index =
	lisp_gpe_tenant_l3_iface_add_or_lock (vni, overlay_table_id,
					      1 /* with_default_route */ );

      vnet_sw_interface_t sub_itf_template = {
	.type = VNET_SW_INTERFACE_TYPE_SUB,
	.flood_class = VNET_FLOOD_CLASS_NORMAL,
	.sup_sw_if_index = main_sw_if_index,
	.sub.id = lisp_gpe_sub_interface_id++,
      };

      if (NULL != vnet_create_sw_interface (vnet_get_main (),
					    &sub_itf_template,
					    &sub_sw_if_index))
	return (INDEX_INVALID);

      pool_get (lisp_gpe_sub_interface_pool, l3s);
      clib_memset (l3s, 0, sizeof (*l3s));
      l3s->key = clib_mem_alloc (sizeof (*l3s->key));
      clib_memset (l3s->key, 0, sizeof (*l3s->key));

      ip_address_copy (&l3s->key->local_rloc, lrloc);
      l3s->key->vni = vni;
      l3s->main_sw_if_index = main_sw_if_index;
      l3s->sw_if_index = sub_sw_if_index;
      l3s->eid_table_id = overlay_table_id;

      l3si = (l3s - lisp_gpe_sub_interface_pool);

      // FIXME. enable When we get an adj
      ip6_sw_interface_enable_disable (l3s->sw_if_index, 1);
      ip4_sw_interface_enable_disable (l3s->sw_if_index, 1);

      vnet_sw_interface_set_flags (vnet_get_main (),
				   l3s->sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      lisp_gpe_sub_interface_db_insert (l3s);
    }
  else
    {
      l3s = lisp_gpe_sub_interface_get_i (l3si);
      l3s->eid_table_id = overlay_table_id;
    }

  lisp_gpe_sub_interface_set_table (l3s->sw_if_index, l3s->eid_table_id);
  l3s->locks++;

  return (l3si);
}

void
lisp_gpe_sub_interface_unlock (index_t l3si)
{
  lisp_gpe_sub_interface_t *l3s;

  l3s = lisp_gpe_sub_interface_get_i (l3si);

  ASSERT (0 != l3s->locks);
  l3s->locks--;

  if (0 == l3s->locks)
    {
      lisp_gpe_sub_interface_unset_table (l3s->sw_if_index,
					  l3s->eid_table_id);

      lisp_gpe_tenant_l3_iface_unlock (l3s->key->vni);
      vnet_sw_interface_set_flags (vnet_get_main (), l3s->sw_if_index, 0);
      vnet_delete_sub_interface (l3s->sw_if_index);

      lisp_gpe_sub_interface_db_remove (l3s);

      clib_mem_free (l3s->key);
      pool_put (lisp_gpe_sub_interface_pool, l3s);
    }
}

const lisp_gpe_sub_interface_t *
lisp_gpe_sub_interface_get (index_t l3si)
{
  return (lisp_gpe_sub_interface_get_i (l3si));
}

u8 *
format_lisp_gpe_sub_interface (u8 * s, va_list * ap)
{
  lisp_gpe_sub_interface_t *l3s = va_arg (*ap, lisp_gpe_sub_interface_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "%-16U",
	      format_vnet_sw_interface_name,
	      vnm, vnet_get_sw_interface (vnm, l3s->sw_if_index));
  s = format (s, "%=8d", l3s->key->vni);
  s = format (s, "%=15d", l3s->sw_if_index);
  s = format (s, "%U", format_ip_address, &l3s->key->local_rloc);

  return (s);
}

/** CLI command to show LISP-GPE interfaces. */
static clib_error_t *
lisp_gpe_sub_interface_show (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  lisp_gpe_sub_interface_t *l3s;

  vlib_cli_output (vm, "%-16s%=8s%=15s%s", "Name", "VNI", "sw_if_index",
		   "local RLOC");

  /* *INDENT-OFF* */
  pool_foreach (l3s, lisp_gpe_sub_interface_pool,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_sub_interface, l3s);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_sub_interface_command) = {
  .path = "show gpe sub-interface",
  .short_help = "show gpe sub-interface",
  .function = lisp_gpe_sub_interface_show,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_gpe_sub_interface_module_init (vlib_main_t * vm)
{
  lisp_gpe_sub_interfaces =
    hash_create_mem (0,
		     sizeof (lisp_gpe_sub_interface_key_t), sizeof (uword));
  lisp_gpe_sub_interfaces_sw_if_index =
    hash_create_mem (0,
		     sizeof (lisp_gpe_sub_interface_key_t), sizeof (uword));

  return (NULL);
}

VLIB_INIT_FUNCTION (lisp_gpe_sub_interface_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
