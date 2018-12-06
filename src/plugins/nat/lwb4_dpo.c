/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/ip/ip.h>
#include <nat/lwb4_dpo.h>

dpo_type_t lwb4_dpo_type;

void
lwb4_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t * dpo)
{
  dpo_set (dpo, lwb4_dpo_type, dproto, aftr_index);
}

u8 *
format_lwb4_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "lwB4: AFTR:%d", index));
}

static void
lwb4_dpo_lock (dpo_id_t * dpo)
{
}

static void
lwb4_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t lwb4_dpo_vft = {
  .dv_lock = lwb4_dpo_lock,
  .dv_unlock = lwb4_dpo_unlock,
  .dv_format = format_lwb4_dpo,
};

const static char *const lwb4_ip4_nodes[] = {
  "lwb4-in2out",
  NULL,
};

const static char *const lwb4_ip6_nodes[] = {
  "lwb4-out2in",
  NULL,
};

const static char *const *const lwb4_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = lwb4_ip4_nodes,
  [DPO_PROTO_IP6] = lwb4_ip6_nodes,
  [DPO_PROTO_MPLS] = NULL,
};

void
lwb4_dpo_module_init (void)
{
  lwb4_dpo_type = dpo_register_new_type (&lwb4_dpo_vft, lwb4_nodes);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
