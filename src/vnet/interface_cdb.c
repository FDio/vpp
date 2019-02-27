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
#include <vlib/cdb/cdb.h>
#include <vnet/vnet.h>

u8 * format_cdb_field_action (u8 * s, va_list * va);

static clib_error_t *
interface_cdb_item_update (char * class, vlib_cdb_object_t * o,
   vlib_cdb_class_item_t *ci, void * v, vlib_cdb_field_action_t action,
   u8 is_verify)
{
  vnet_main_t * vm = vnet_get_main ();
  u32 flags = 0;

  if (strcmp(ci->name, "admin-state"))
    return 0;

  if (!is_verify)
    return 0;

  if (action == CDB_FIELD_ACTION_SET)
    flags = VNET_SW_INTERFACE_FLAG_ADMIN_UP;

  u32 sw_if_index = ~0;
  unformat_input_t input;
  unformat_init_vector (&input, vec_dup (o->name));
  if (!unformat_user (&input, unformat_vnet_sw_interface, vm, &sw_if_index))
    {
      unformat_free (&input);
      return clib_error_return (0, "unknown interface `%s'", o->name);
    }
  unformat_free (&input);

  return vnet_sw_interface_set_flags(vm, sw_if_index, flags);
}

clib_error_t *
interface_cdb_init (vlib_main_t *vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vlib_cdb_init)))
    return error;

  vlib_cdb_register_commit_cb ("interface", NULL, interface_cdb_item_update);
  return error;
}

VLIB_INIT_FUNCTION (interface_cdb_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
