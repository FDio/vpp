#ifndef _NODE_OUT_H_
#define _NODE_OUT_H_

typedef enum {
  ACL_OUT_ERROR_DROP,
  ACL_OUT_INTERFACE_OUTPUT,
  ACL_OUT_L2S_OUTPUT_IP4_ADD,
  ACL_OUT_L2S_OUTPUT_IP6_ADD,
  ACL_OUT_N_NEXT,
} acl_out_next_t;

#endif
