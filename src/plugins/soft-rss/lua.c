/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Cisco and/or its affiliates. */

#include <vlua/vlua.h>
#include <vnet/vnet.h>
#include <soft-rss/export.h>
#include <vnet/interface_funcs.h>

typedef struct
{
  u32 sw_if_index;
} vlua_interface_ns_ctx_t;

static u32
get_hw_if_index (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vnet_sw_interface_t *sw;

  if (!ctx || args->context_size < sizeof (*ctx))
    return ~0;

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw || sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return ~0;

  return sw->hw_if_index;
}

static clib_error_t *
l_soft_rss_configure (vlua_method_fn_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 hw_if_index = get_hw_if_index (args);
  vlua_val_t *config_table = args->args;
  soft_rss_config_t config = {};
  const vlua_val_t *val;

  if (hw_if_index == ~0)
    return clib_error_return (0, "invalid interface (must be hardware interface)");

  if (!vlua_val_type_is_table (config_table))
    return clib_error_return (0, "table argument expected");

  /* Default values */
  config.type = SOFT_RSS_TYPE_4_TUPLE;

  /* Parse config table */
  val = vlua_val_table_get_entry (config_table, "type");
  if (val && vlua_val_type_is_string (val))
    {
      const u8 *s = vlua_val_get_string (val, 0);
      if (0)
	;
#define _(a, b)                                                               \
  else if (!strcmp ((char *) s, b)) config.type = SOFT_RSS_TYPE_##a;
      foreach_soft_rss_type
#undef _
	else return clib_error_return (0, "unknown type '%s'", s);
    }

  val = vlua_val_table_get_entry (config_table, "ip4_only");
  if (val && vlua_val_type_is_bool (val))
    config.ip4_only = vlua_val_get_bool (val);

  val = vlua_val_table_get_entry (config_table, "ip6_only");
  if (val && vlua_val_type_is_bool (val))
    config.ip6_only = vlua_val_get_bool (val);

  val = vlua_val_table_get_entry (config_table, "with_main_thread");
  if (val && vlua_val_type_is_bool (val))
    config.with_main_thread = vlua_val_get_bool (val);

  val = vlua_val_table_get_entry (config_table, "l2_hdr_offset");
  if (val && vlua_val_type_is_integer (val))
    config.l2_hdr_offset = (u16) vlua_val_get_integer (val);

  /* Parse threads bitmap from array of thread indices */
  val = vlua_val_table_get_entry (config_table, "threads");
  if (val && vlua_val_type_is_table (val))
    {
      /* Iterate over array part of table 1..N */
      /* Since we don't have direct array iterator exposed yet, we assume 1-based integer keys */
      /* Or we rely on vlua_val_table_get_entry with string keys "1", "2" etc?
       * The current vlua implementation stores table as array of key/value pairs.
       * We can iterate over all entries.
       */
       /* TODO: proper table iteration. For now, let's assume user passes array-like table.
          Wait, vlua_val_t for table exposes table_entries vector. We can iterate it. */
       /* BUT, vlua_val_t is opaque or internal. We are inside plugin.
          Wait, we included <vlua/vlua.h>. Does it expose vlua_val_t structure?
          Yes, it's in vlua.h */
       
       vlua_table_entry_t *entry;
       /* We need to check if keys are integers or if we iterate all values. 
          Lua tables used as arrays usually have integer keys.
          However, vlua_val_t stores keys as strings "1", "2" etc. if they came from Lua?
          Actually vlua_val_from_lua (value.c) converts all keys to strings currently?
          Let's check value.c:
            if (!lua_isstring (L, -2)) ... continue; 
          It only accepts string keys.
          Lua treats numbers as keys, but lua_isstring returns true for numbers too?
          Yes, but lua_tolstring converts number to string in-place on stack! 
          So array indices "1", "2" will be strings.
       */
       /* Iterate all entries and try to parse values as thread indices */
       vec_foreach (entry, val->table_entries)
       {
         if (vlua_val_type_is_integer (&entry->value))
           config.threads = clib_bitmap_set (config.threads, vlua_val_get_integer (&entry->value), 1);
         else if (vlua_val_type_is_number (&entry->value))
            config.threads = clib_bitmap_set (config.threads, (uword)vlua_val_get_number (&entry->value), 1);
       }
    }

  /* Parse key (byte array from string) */
  val = vlua_val_table_get_entry (config_table, "key");
  if (val && vlua_val_type_is_string (val))
    {
      u32 len = 0;
      const u8 *k = vlua_val_get_string (val, &len);
      vec_add (config.key, k, len);
    }

  clib_error_t *err = soft_rss_config (vm, &config, hw_if_index);

  clib_bitmap_free (config.threads);
  vec_free (config.key);

  return err;
}

static clib_error_t *
l_soft_rss_enable (vlua_method_fn_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 hw_if_index = get_hw_if_index (args);

  if (hw_if_index == ~0)
    return clib_error_return (0, "invalid interface");

  return soft_rss_enable (vm, hw_if_index);
}

static clib_error_t *
l_soft_rss_disable (vlua_method_fn_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 hw_if_index = get_hw_if_index (args);

  if (hw_if_index == ~0)
    return clib_error_return (0, "invalid interface");

  return soft_rss_disable (vm, hw_if_index);
}

static clib_error_t *
l_soft_rss_clear (vlua_method_fn_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 hw_if_index = get_hw_if_index (args);

  if (hw_if_index == ~0)
    return clib_error_return (0, "invalid interface");

  return soft_rss_clear (vm, hw_if_index);
}

static clib_error_t *
soft_rss_lua_init (vlua_handle_t h, vlua_init_fn_args_t *a)
{
  vlua_table_handle_t iface = a->table_handles[0];
  vlua_table_handle_t srss;
  vlua_method_handle_t mh;

  /* Create .interface.soft_rss table */
  srss = vlua_table_add (h, "soft_rss", iface);

  mh = vlua_method_add (h, srss, "configure");
  vlua_method_add_call_args (mh, l_soft_rss_configure, 1, VLUA_T_TABLE);

  mh = vlua_method_add (h, srss, "enable");
  vlua_method_add_call_args (mh, l_soft_rss_enable, 0);

  mh = vlua_method_add (h, srss, "disable");
  vlua_method_add_call_args (mh, l_soft_rss_disable, 0);

  mh = vlua_method_add (h, srss, "clear");
  vlua_method_add_call_args (mh, l_soft_rss_clear, 0);

  return 0;
}

VLUA_REGISTER_INIT_FN (soft_rss) = {
  .init_fn = soft_rss_lua_init,
  .paths = VLUA_PATHS (".interface"),
};
