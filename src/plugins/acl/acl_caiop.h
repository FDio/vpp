#ifndef vpp_acl_caiop_h
#define vpp_acl_caiop_h

#include <plugins/acl/acl.h>

int is_acl_caiop_enabled_on_sw_if_index (u32 sw_if_index, int is_input);
int acl_caiop_add_del (int is_add, u32 sw_if_index, int is_input,
		       acl_plugin_private_caiop_match_5tuple_func_t func);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
