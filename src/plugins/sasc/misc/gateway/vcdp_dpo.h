// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

typedef struct {
  dpo_proto_t proto;
  u16 tenant_idx;
  dpo_id_t dpo_parent; // Stacked DPO
} vcdp_dpo_t;

typedef struct {
  fib_node_t node;
  fib_node_index_t fib_entry;
  u32 sibling;
} vcdp_fib_t;

void vcdp_dpo_entry(u32 fib_index, ip_prefix_t *prefix, u16 index, bool is_interpose);
vcdp_dpo_t *vcdp_dpo_get(index_t index);

