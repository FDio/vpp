#!/usr/bin/perl
#
  
my $func_count = 1 << 6;
print <<EE;

/* 
 * DO NOT MODIFY manually - use the dataplane-codegen.pl to regenerate.
 */

EE

for my $i (0..$func_count-1) {
        print <<EE;
static uword
acl_node_func_wrapper_$i(vlib_main_t * vm,
                      vlib_node_runtime_t * node, vlib_frame_t * frame) {

   acl_fa_node_common_prepare_fn (vm, node, frame, $i & ACL_NODE_IS_IP6,
           $i & ACL_NODE_IS_INPUT, $i & ACL_NODE_IS_L2_PATH, 
           $i & ACL_NODE_IS_STATEFUL);

   return acl_fa_inner_node_fn(vm, node, frame, $i & ACL_NODE_IS_IP6,
           $i & ACL_NODE_IS_INPUT, $i & ACL_NODE_IS_L2_PATH,
           $i & ACL_NODE_IS_STATEFUL, $i & ACL_NODE_IS_TRACE,
           $i & ACL_NODE_IS_RECLASSIFY);
}
                  
EE
}

print <<EE;
always_inline uword acl_fa_node_function(vlib_main_t * vm,
                      vlib_node_runtime_t * node, vlib_frame_t * frame,
                      uword func_selector)
{
        switch(func_selector) {
EE

for my $i (0..$func_count-1) {
        print <<EE;
                case $i: return acl_node_func_wrapper_$i(vm, node, frame);
EE
}
print <<EE;
                default: clib_error("ACL plugin: invalid function selector");
        }
	ASSERT(0);
	return 0;
}
EE


