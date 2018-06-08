/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <igmp/igmp_ssm_range.h>

typedef struct igmp_group_prefix_t
{
  fib_prefix_t igp_prefix;
  igmp_group_prefix_type_t igp_type;
} igmp_group_prefix_t;

static igmp_group_prefix_t *igmp_group_prefixs;

u8 *
format_igmp_group_prefix_type (u8 * s, va_list * args)
{
  igmp_group_prefix_type_t type = va_arg (*args, int);

  switch (type)
    {
#define _(n,f) case IGMP_GROUP_PREFIX_TYPE_##f: return (format (s, "%s", #f));
      foreach_igmp_group_prefix_type
#undef _
    }
  return format (s, "unknown:%d", type);
}

static int
igmp_group_prefix_cmp (const igmp_group_prefix_t * gp1,
		       const fib_prefix_t * p)
{
  return (fib_prefix_cmp (&gp1->igp_prefix, p));
}

void
igmp_group_prefix_set (const fib_prefix_t * pfx,
		       igmp_group_prefix_type_t type)
{
  u32 pos;

  pos =
    vec_search_with_function (igmp_group_prefixs, pfx, igmp_group_prefix_cmp);

  if ((~0 == pos) && (IGMP_GROUP_PREFIX_TYPE_SSM == type))
    {
      igmp_group_prefix_t gp = {
	.igp_prefix = *pfx,
	.igp_type = type,
      };

      vec_add1 (igmp_group_prefixs, gp);
    }
  if ((~0 != pos) && (IGMP_GROUP_PREFIX_TYPE_ASM == type))
    {
      vec_del1 (igmp_group_prefixs, pos);
    }
}

static void
igmp_ssm_range_populate (void)
{
  igmp_group_prefix_t *ssm_default;

  vec_add2 (igmp_group_prefixs, ssm_default, 1);

  ssm_default->igp_prefix.fp_addr.ip4.as_u32 = IGMP_SSM_DEFAULT;
  ssm_default->igp_prefix.fp_proto = FIB_PROTOCOL_IP4;
  ssm_default->igp_prefix.fp_len = 8;
  ssm_default->igp_type = IGMP_GROUP_PREFIX_TYPE_SSM;
}

igmp_group_prefix_type_t
igmp_group_prefix_get_type (const ip46_address_t * gaddr)
{
  igmp_group_prefix_t *igp;

  vec_foreach (igp, igmp_group_prefixs)
  {
    if (ip4_destination_matches_route (&ip4_main,
				       &gaddr->ip4,
				       &igp->igp_prefix.fp_addr.ip4,
				       igp->igp_prefix.fp_len))
      return (IGMP_GROUP_PREFIX_TYPE_SSM);
  }

  return (IGMP_GROUP_PREFIX_TYPE_ASM);
}

void
igmp_ssm_range_walk (igmp_ssm_range_walk_t fn, void *ctx)
{
  igmp_group_prefix_t *igp;

  vec_foreach (igp, igmp_group_prefixs)
  {
    if (WALK_STOP == fn (&igp->igp_prefix, igp->igp_type, ctx))
      break;
  }
}

static clib_error_t *
igmp_ssm_range_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  igmp_group_prefix_t *igp;

  vec_foreach (igp, igmp_group_prefixs)
  {
    vlib_cli_output (vm, "%U => %U",
		     format_fib_prefix, &igp->igp_prefix,
		     format_igmp_group_prefix_type, igp->igp_type);
  }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_show_timers_command, static) = {
  .path = "show igmp ssm-ranges",
  .short_help = "show igmp ssm-ranges",
  .function = igmp_ssm_range_show,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_ssm_range_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, igmp_init)))
    return error;

  igmp_ssm_range_populate ();

  IGMP_DBG ("ssm-range-initialized");

  return (error);
}

VLIB_INIT_FUNCTION (igmp_ssm_range_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
