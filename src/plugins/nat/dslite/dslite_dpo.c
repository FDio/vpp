/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <nat/dslite/dslite_dpo.h>

dpo_type_t dslite_dpo_type;
dpo_type_t dslite_ce_dpo_type;

void
dslite_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t * dpo)
{
  dpo_set (dpo, dslite_dpo_type, dproto, aftr_index);
}

void
dslite_ce_dpo_create (dpo_proto_t dproto, u32 b4_index, dpo_id_t * dpo)
{
  dpo_set (dpo, dslite_ce_dpo_type, dproto, b4_index);
}

u8 *
format_dslite_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "DS-Lite: AFTR:%d", index));
}

u8 *
format_dslite_ce_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "DS-Lite: B4:%d", index));
}

static void
dslite_dpo_lock (dpo_id_t * dpo)
{
}

static void
dslite_dpo_unlock (dpo_id_t * dpo)
{
}

static void
dslite_ce_dpo_lock (dpo_id_t * dpo)
{
}

static void
dslite_ce_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t dslite_dpo_vft = {
  .dv_lock = dslite_dpo_lock,
  .dv_unlock = dslite_dpo_unlock,
  .dv_format = format_dslite_dpo,
};

const static dpo_vft_t dslite_ce_dpo_vft = {
  .dv_lock = dslite_ce_dpo_lock,
  .dv_unlock = dslite_ce_dpo_unlock,
  .dv_format = format_dslite_ce_dpo,
};

const static char *const dslite_ip4_nodes[] = {
  "dslite-out2in",
  NULL,
};

const static char *const dslite_ip6_nodes[] = {
  "dslite-in2out",
  NULL,
};

const static char *const dslite_ce_ip4_nodes[] = {
  "dslite-ce-encap",
  NULL,
};

const static char *const dslite_ce_ip6_nodes[] = {
  "dslite-ce-decap",
  NULL,
};

const static char *const *const dslite_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = dslite_ip4_nodes,
  [DPO_PROTO_IP6] = dslite_ip6_nodes,
  [DPO_PROTO_MPLS] = NULL,
};

const static char *const *const dslite_ce_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = dslite_ce_ip4_nodes,
  [DPO_PROTO_IP6] = dslite_ce_ip6_nodes,
  [DPO_PROTO_MPLS] = NULL,
};

void
dslite_dpo_module_init (void)
{
  dslite_dpo_type = dpo_register_new_type (&dslite_dpo_vft, dslite_nodes);
  dslite_ce_dpo_type = dpo_register_new_type (&dslite_ce_dpo_vft,
					      dslite_ce_nodes);
}
