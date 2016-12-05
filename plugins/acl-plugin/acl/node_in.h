#ifndef _NODE_IN_H_
#define _NODE_IN_H_

typedef enum {
  ACL_IN_ERROR_DROP,
  ACL_IN_ETHERNET_INPUT,
  ACL_IN_L2S_INPUT_IP4_ADD,
  ACL_IN_L2S_INPUT_IP6_ADD,
  ACL_IN_N_NEXT,
} acl_in_next_t;

#endif
