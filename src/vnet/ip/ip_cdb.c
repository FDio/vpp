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
#include <vnet/lisp-cp/lisp_types.h>
#include <vlib/cdb/cdb.h>
#include <vppinfra/clib_error.h>

clib_error_t *
cdb_ip_cb (char * class, vlib_cdb_object_t * o,
   vlib_cdb_class_item_t *ci, void * v, vlib_cdb_field_action_t action,
   u8 is_verify)
{
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  vnet_main_t *vm = vnet_get_main ();

  unformat_input_t input;
  unformat_init_vector (&input, vec_dup (o->name));
  if (!unformat_user (&input, unformat_vnet_sw_interface, vm, &sw_if_index))
    {
      unformat_free (&input);
      return clib_error_return (0, "unknown interface `%s'", o->name);
    }
  unformat_free (&input);

  u8 is_del = CDB_FIELD_ACTION_UNSET == action ? 1 : 0;

  ip_prefix_t *p = v;
  u8 is_ip4 = ip_addr_version(&p->addr) == IP4 ? 1 : 0;

  if (!is_verify)
  {
    if (is_ip4)
      error = ip4_add_del_interface_address (vlib_get_main(), sw_if_index,
          &ip_addr_v4(&p->addr), p->len, is_del);
    else
      error = ip6_add_del_interface_address (vlib_get_main(), sw_if_index,
          &ip_addr_v6(&p->addr), p->len, is_del);
  }

  return error;
}

static int
cdb_ip_address_cmp (void * a1, void * a2)
{
  return ip_address_cmp ((void *)a1, (void *)a2);
}

uword
unformat_interface_address (unformat_input_t * input, va_list * args)
{
  ip_prefix_t *a = va_arg (*args, ip_prefix_t *);
  if (unformat (input, "%U/%d", unformat_ip_address, &ip_prefix_addr (a),
		&ip_prefix_len (a)))
    {
      if ((ip_prefix_version (a) == IP4 && 32 < ip_prefix_len (a)) ||
	  (ip_prefix_version (a) == IP6 && 128 < ip_prefix_length (a)))
        return 0;
    }
  else
    return 0;
  return 1;
}

VLIB_REGISTER_CDB_TYPE (interface_address) = {
  .name = "interface-address",
  .size = sizeof (ip_prefix_t),
  .format = format_ip_prefix,
  .unformat = unformat_interface_address,
  .compare = cdb_ip_address_cmp,
};

VLIB_REGISTER_CDB_CLASS_ITEM (interface_ip46_address) = {
  .class = "interface",
  .name = "interface-address",
  .type = "interface-address",
  .description = "interface IP address",
  .flags = CDB_CLASS_ITEM_IS_MULTIPLE,
};

clib_error_t *
ip_cdb_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vlib_cdb_init)))
      return error;

  vlib_cdb_register_commit_cb ("interface", NULL, cdb_ip_cb);

  return 0;
}

VLIB_INIT_FUNCTION (ip_cdb_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
