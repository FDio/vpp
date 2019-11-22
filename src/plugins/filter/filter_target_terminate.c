/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <filter/filter_target_terminate.h>

/**
 * Exposed DP types and function
 */
static dpo_id_t filter_target_terminates[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS];
static dpo_type_t filter_target_terminate_type[FILTER_N_BASE_HOOKS];

const dpo_id_t *
filter_target_terminate_get (dpo_proto_t proto, filter_hook_type_t fht)
{
  return (&filter_target_terminates[proto][fht]);
}

static void
filter_target_terminate_lock (dpo_id_t * dpo)
{
}

static void
filter_target_terminate_unlock (dpo_id_t * dpo)
{
}

u8 *
format_filter_target_terminate (u8 * s, va_list * args)
{
  CLIB_UNUSED (index_t ftti) = va_arg (*args, index_t);

  s = format (s, "terminate");

  return (s);
}

const static dpo_vft_t filter_target_terminate_vft = {
  .dv_lock = filter_target_terminate_lock,
  .dv_unlock = filter_target_terminate_unlock,
  .dv_format = format_filter_target_terminate,
};

const static char *const filter_target_terminate_input_ip4_nodes[] = {
  "filter-target-terminate-input-ip4",
  NULL,
};

const static char *const filter_target_terminate_input_ip6_nodes[] = {
  "filter-target-terminate-input-ip6",
  NULL,
};

const static char *const filter_target_terminate_output_ip4_nodes[] = {
  "filter-target-terminate-output-ip4",
  NULL,
};

const static char *const filter_target_terminate_output_ip6_nodes[] = {
  "filter-target-terminate-output-ip6",
  NULL,
};

const static char *const filter_target_terminate_drop_ip4_nodes[] = {
  "ip4-drop",
  NULL,
};

const static char *const filter_target_terminate_drop_ip6_nodes[] = {
  "ip6-drop",
  NULL,
};

/* *INDENT-OFF* */
const static char *const *const filter_target_terminate_nodes[FILTER_N_BASE_HOOKS][DPO_PROTO_NUM] = {
  [FILTER_HOOK_INPUT] = {
    [DPO_PROTO_IP4] = filter_target_terminate_input_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_terminate_input_ip6_nodes,
  },
  [FILTER_HOOK_OUTPUT] = {
    [DPO_PROTO_IP4] = filter_target_terminate_output_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_terminate_output_ip6_nodes,
  },
  [FILTER_HOOK_FORWARD] = {
    [DPO_PROTO_IP4] = filter_target_terminate_drop_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_terminate_drop_ip6_nodes,
  },
  [FILTER_HOOK_FOR_US] = {
    [DPO_PROTO_IP4] = filter_target_terminate_drop_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_terminate_drop_ip6_nodes,
  },
  [FILTER_HOOK_FROM_US] = {
    [DPO_PROTO_IP4] = filter_target_terminate_drop_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_terminate_drop_ip6_nodes,
  },
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_terminate_init (vlib_main_t * vm)
{
  filter_hook_type_t fht;
  dpo_proto_t dproto;

  FOREACH_FILTER_HOOK_BASE_TYPE (fht)
  {
    filter_target_terminate_type[fht] =
      dpo_register_new_type (&filter_target_terminate_vft,
			     filter_target_terminate_nodes[fht]);

    FOR_EACH_DPO_PROTO (dproto)
    {
      dpo_set (&filter_target_terminates[dproto][fht],
	       filter_target_terminate_type[fht], dproto, 0);
    }
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_terminate_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
