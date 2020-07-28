#ifndef vpp_acl_plugin_util_h
#define vpp_acl_plugin_util_h

#define acl_cli_output_u(vm, value)                                           \
  vlib_cli_output (vm, "  %s: %u", #value, value)
#define acl_cli_output_bitmap(vm, bitmap)                                     \
  vlib_cli_output (vm, "  %s bitmap: %U", #bitmap, format_bitmap_hex, bitmap)

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
