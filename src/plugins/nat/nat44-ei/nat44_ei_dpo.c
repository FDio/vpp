/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <nat/nat44-ei/nat44_ei_dpo.h>

dpo_type_t nat_dpo_type;

void
nat_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t *dpo)
{
  dpo_set (dpo, nat_dpo_type, dproto, aftr_index);
}

u8 *
format_nat_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "NAT44 out2in: AFTR:%d", index));
}

static void
nat_dpo_lock (dpo_id_t *dpo)
{
}

static void
nat_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t nat_dpo_vft = {
  .dv_lock = nat_dpo_lock,
  .dv_unlock = nat_dpo_unlock,
  .dv_format = format_nat_dpo,
};

const static char *const nat_ip4_nodes[] = {
  "nat44-ei-out2in",
  NULL,
};

const static char *const nat_ip6_nodes[] = {
  NULL,
};

const static char *const *const nat_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = nat_ip4_nodes,
  [DPO_PROTO_IP6] = nat_ip6_nodes,
  [DPO_PROTO_MPLS] = NULL,
};

void
nat_dpo_module_init (void)
{
  nat_dpo_type = dpo_register_new_type (&nat_dpo_vft, nat_nodes);
}
