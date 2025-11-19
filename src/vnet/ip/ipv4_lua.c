/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/interface/lua.h>

static clib_error_t *
ipv4_add_del_addr (vnet_main_t *vnm, u32 sw_if_index, const vlua_val_t *val)
{
  const u8 *str;
  ip4_address_t addr;
  u32 len;
  unformat_input_t in;
  clib_error_t *err = 0;

  if (!vlua_val_type_is_string (val))
    return clib_error_return (0, "address must be string");

  str = vlua_val_get_string (val, 0);
  unformat_init_vector (&in, vec_dup ((u8 *) str));

  if (unformat (&in, "%U/%d", unformat_ip4_address, &addr, &len))
    {
      err = ip4_add_del_interface_address (vnm->vlib_main, sw_if_index, &addr,
					   len, 0 /* is_del */);
    }
  else
    err = clib_error_return (0, "invalid ipv4 address '%s'", str);

  unformat_free (&in);
  return err;
}

static clib_error_t *
ipv4_config_handler (vnet_main_t *vnm, u32 sw_if_index,
		     const vlua_val_t *config)
{
  const vlua_val_t *val;
  clib_error_t *err;

  if (!vlua_val_type_is_table (config))
    return clib_error_return (0, "ipv4 config must be a table");

  val = vlua_val_table_get_entry (config, "address");
  if (val)
    {
      err = ipv4_add_del_addr (vnm, sw_if_index, val);
      if (err)
	return err;
    }

  val = vlua_val_table_get_entry (config, "secondary_addresses");
  if (val && vlua_val_type_is_table (val))
    {
      vlua_table_entry_t *e;
      vec_foreach (e, val->table_entries)
	{
	  /* Indices are usually 1, 2, 3 for arrays, but values are what matters */
	  err = ipv4_add_del_addr (vnm, sw_if_index, &e->value);
	  if (err)
	    return err;
	}
    }

  return 0;
}

static clib_error_t *
vpp_lua_ipv4_init (vlib_main_t *vm)
{
  vlua_register_interface_config_handler ("ipv4", ipv4_config_handler);
  return 0;
}

VLIB_INIT_FUNCTION (vpp_lua_ipv4_init);
