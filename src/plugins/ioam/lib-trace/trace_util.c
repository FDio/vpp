/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <vppinfra/mem.h>
#include "trace_util.h"
#include "trace_config.h"

trace_main_t trace_main;

static int
trace_profile_cleanup (trace_profile * profile)
{
  clib_memset (profile, 0, sizeof (trace_profile));
  ip6_trace_profile_cleanup ();	/* lib-trace_TODO: Remove this once IOAM-IPv6 transport is a plugin */
  return 0;
}

static int
trace_main_profiles_reset (void)
{
  int rv;

  trace_main_t *sm = &trace_main;
  rv = trace_profile_cleanup (&(sm->profile));
  return (rv);
}

int
trace_util_init (void)
{
  int rv;

  rv = trace_main_profiles_reset ();
  return (rv);
}

int
trace_profile_create (trace_profile * profile, trace_profile * user_defined)
{
  if (profile && !profile->valid)
    {
      // Set the rest of the vars
      profile->namespace_id = user_defined->namespace_id;
      profile->num_elts = user_defined->num_elts;
      profile->node_id_short = user_defined->node_id_short;
      profile->node_id_wide = user_defined->node_id_wide;
      profile->app_data_short = user_defined->app_data_short;
      profile->app_data_wide = user_defined->app_data_wide;
      profile->option_type = user_defined->option_type;
      profile->node_type = user_defined->node_type;
      profile->trace_type = user_defined->trace_type;
      profile->ts_format = user_defined->ts_format;
      profile->queue_depth_type = user_defined->queue_depth_type;
      profile->valid = 1;
      profile->opaque.len_schemeid = user_defined->opaque.len_schemeid;
      if (user_defined->opaque.data)
	{
	  vlib_cli_output (vlib_get_main (),
			   "Trace Profile Create: Adding %d-bytes of opaque data...\n");
	  u32 olen = IOAM_GET_OPAQUE_LEN (user_defined->opaque.len_schemeid);	// Represented as 4 octets
	  u32 i;
	  for (i = 0; i < olen; i++)
	    {
	      // Freaking endianess
	      profile->opaque.data[i] =
		clib_host_to_net_u32 (user_defined->opaque.data[i]);
	    }
	  vec_free (user_defined->opaque.data);
	}

      /* lib-trace_TODO: Remove this once IOAM-IPv6 transport is a plugin */
      ip6_trace_profile_setup ();
      return (0);
    }
  return (-1);
}

clib_error_t *
clear_trace_profile_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  trace_main_profiles_reset ();
  return 0;
}

void
clear_trace_profiles (void)
{
  clear_trace_profile_command_fn (0, 0, 0);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(clear_trace_profile_command) =
{
.path = "clear ioam-trace profile",
.short_help = "clear ioam-trace profile [<index>|all]",
.function = clear_trace_profile_command_fn,
};

/* *INDENT-ON* */

static clib_error_t *
show_trace_profile_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  trace_profile *p = NULL;
  p = trace_profile_find ();
  u8 *s = 0;
  if (!(p && p->valid))
    {
      s = format (s, "\nTrace configuration not valid\n");
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      return 0;
    }
  s = format (s, " HOP BY HOP OPTIONS - TRACE CONFIG - \n");
  s = format (s, "        iOAM Namespace      : %d\n", p->namespace_id);
  s = format (s, "        iOAM Type           : %d ", p->option_type);
  u8 *stmp = 0;
  if (p->option_type & IOAM_OPTION_PREALLOC)
    {
      stmp = format (stmp, " - Preallocation");
    }
  if (p->option_type & IOAM_OPTION_INCREMENT)
    {
      stmp = format (stmp, " - Incremental");
    }
  if (p->option_type & IOAM_OPTION_POT)
    {
      stmp = format (stmp, " - Proof-of-Transit");
    }
  if (p->option_type & IOAM_OPTION_E2E)
    {
      stmp = format (stmp, " - Edge-to-Edge");
    }
  s = format (s, "(%s)\n", stmp);
  s = format (s, "        Trace Type          : 0x%x\n", p->trace_type);
  s =
    format (s, "        Timestamp precision : %d (%s)\n",
	    p->ts_format,
	    (p->ts_format ==
	     IOAM_TSP_SECONDS) ? "Seconds" : ((p->ts_format ==
					       IOAM_TSP_MILLISECONDS) ?
					      "Milliseconds"
					      : (((p->ts_format ==
						   IOAM_TSP_MICROSECONDS) ?
						  "Microseconds" :
						  "Nanoseconds"))));
  s = format (s, "        Num of trace nodes  : %d\n", p->num_elts);
  s =
    format (s, "        Node-ID-Short/Type  : %d / %s\n",
	    p->node_id_short,
	    (p->node_type == IOAM_NODE_ENCAP) ? "Encap" :
	    ((p->node_type == IOAM_NODE_TRANSIT) ? "Transit" : "Decap"));
  s = format (s, "        App Data-Short      : 0x%x\n", p->app_data_short);
  s =
    format (s, "        Node-ID-Wide/Type   : 0x%Lx / %s\n",
	    p->node_id_wide,
	    (p->node_type == IOAM_NODE_ENCAP) ? "Encap" :
	    ((p->node_type == IOAM_NODE_TRANSIT) ? "Transit" : "Decap"));
  s = format (s, "        App Data-Wide       : 0x%Lx\n", p->app_data_wide);
  s =
    format (s, "        Queue Depth-Type    : %s\n",
	    (p->queue_depth_type == QUEUE_DEPTH_AF_PACKET) ? "AF_PACKET" :
	    ((p->queue_depth_type == QUEUE_DEPTH_DPDK) ? "DPDK" : "NON"));
  s = format (s, "        Opaque Length/ID    : %d / %d\n",
	      IOAM_GET_OPAQUE_LEN (p->opaque.len_schemeid) << 2,
	      p->opaque.len_schemeid & IOAM_OPAQUE_SCHEMEID_MASK);
  if (IOAM_GET_OPAQUE_LEN (p->opaque.len_schemeid))
    {
      u32 indent = format_get_indent (s);
      s = format (s, "        Opaque Data         : \n        %U%U",
		  format_white_space, indent,
		  format_hex_bytes, p->opaque.data,
		  IOAM_GET_OPAQUE_LEN (p->opaque.len_schemeid) << 2);
    }
  vlib_cli_output (vm, "%v", s);
  vec_free (stmp);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_trace_profile_command, static) =
{
.path = "show ioam-trace profile",
.short_help = "show ioam-trace profile",
.function = show_trace_profile_command_fn,
};
/* *INDENT-ON* */

uword
unformat_option_type (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  *result = 0;
  u8 tmp = 0;
  do
    {
      if (unformat (input, "prealloc"))
	{
	  *result |= IOAM_OPTION_PREALLOC;
	}
      else if (unformat (input, "increment"))
	{
	  *result |= IOAM_OPTION_INCREMENT;
	}
      else if (unformat (input, "pot"))
	{
	  *result |= IOAM_OPTION_POT;
	}
      else if (unformat (input, "e2e"))
	{
	  *result |= IOAM_OPTION_E2E;
	}
    }
  while (tmp++ < 4);
  if ((*result & IOAM_OPTION_PREALLOC) && (*result & IOAM_OPTION_INCREMENT))
    {
      vlib_cli_output (vlib_get_main (),
		       "WARNING: option-type (0x%x) contains both prealloc and increment, defaulting to prealloc",
		       *result);
      *result &= ~(IOAM_OPTION_INCREMENT);
    }
  if (*result == 0)
    {
      vlib_cli_output (vlib_get_main (),
		       "WARNING: No option-type chosen, defaulting to prealloc");
      *result = IOAM_OPTION_PREALLOC;
    }
  return 1;
}

uword
unformat_node_type (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  *result = 99;			// For input check later

  if (unformat (input, "encap"))
    {
      *result = IOAM_NODE_ENCAP;
    }
  else if (unformat (input, "transit"))
    {
      *result = IOAM_NODE_TRANSIT;
    }
  else if (unformat (input, "decap"))
    {
      *result = IOAM_NODE_DECAP;
    }
  return 1;
}

uword
unformat_ts_format (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  *result = 99;			// For input check later

  if (unformat (input, "sec"))
    {
      *result = IOAM_TSP_SECONDS;
    }
  else if (unformat (input, "ms"))
    {
      *result = IOAM_TSP_MILLISECONDS;
    }
  else if (unformat (input, "us"))
    {
      *result = IOAM_TSP_MICROSECONDS;
    }
  else if (unformat (input, "ns"))
    {
      *result = IOAM_TSP_NANOSECONDS;
    }
  return 1;
}

uword
unformat_queue_depth_format (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  *result = 99;			// For input check later

  if (unformat (input, "drv-af-packet"))
    {
      *result = QUEUE_DEPTH_AF_PACKET;
    }
  else if (unformat (input, "drv-dpdk"))
    {
      *result = QUEUE_DEPTH_DPDK;
    }
  return 1;
}

static u8 *
trace_util_check_input (u8 * inerror, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  trace_profile *input = va_arg (*args, trace_profile *);
  u32 *olen = va_arg (*args, u32 *);
  u32 *oid = va_arg (*args, u32 *);
  // Invalid instruction
  if ((input->trace_type & ~IOAM_INSTR_BITMAP_MASK) | (!input->trace_type))
    {
      inerror =
	format (inerror, " - ERROR: Invalid trace-type (0x%x)\n",
		input->trace_type);
    }
  // check validity of option type
  u8 all_options =
    IOAM_OPTION_PREALLOC | IOAM_OPTION_INCREMENT | IOAM_OPTION_POT |
    IOAM_OPTION_E2E;
  if (input->option_type & ~all_options)
    {
      inerror =
	format (inerror,
		" - ERROR: Invalid option-type - [prealloc | increment | pot | e2e]\n");
    }
  if (input->option_type == 0)
    {
      vlib_cli_output (vm,
		       "WARNING: No option-type chosen, defaulting to prealloc");
      input->option_type = IOAM_OPTION_PREALLOC;
    }
  u8 all_nodes = IOAM_NODE_ENCAP | IOAM_NODE_TRANSIT | IOAM_NODE_DECAP;
  if ((input->node_type & ~all_nodes) | !input->node_type)
    {
      inerror =
	format (inerror,
		" - ERROR: Invalid node-type - [encap | transit | decap]\n");
    }
  if (!input->num_elts)
    {
      inerror = format (inerror, " - ERROR: num-elts must be > 0\n");
    }
  if (((input->trace_type & IOAM_BIT_TTL_NODEID_SHORT) == 0)
      && ((input->trace_type & IOAM_BIT_TTL_NODEID_WIDE) == 0))
    {
      inerror =
	format (inerror,
		" - ERROR: Node ID (short or wide) is required and must be > 0\n");
    }
  if ((input->trace_type & IOAM_BIT_TTL_NODEID_SHORT)
      && !input->node_id_short)
    {
      inerror = format (inerror, " - ERROR: node-id-short must be > 0\n");
    }
  if ((input->trace_type & IOAM_BIT_TTL_NODEID_WIDE) && !input->node_id_wide)
    {
      inerror = format (inerror, " - ERROR: node-id-wide must be > 0\n");
    }
  if ((input->trace_type & IOAM_BIT_TIMESTAMP_SUB_SEC)
      && (input->ts_format >= IOAM_TSP_OPTION_SIZE))
    {
      inerror =
	format (inerror,
		" - ERROR: ts-format-sub must be - [sec | ms | us | ns]\n");
    }
  u8 all_depth_types = QUEUE_DEPTH_AF_PACKET | QUEUE_DEPTH_DPDK;
  if ((input->trace_type & IOAM_BIT_QUEUE_DEPTH)
      && ((input->queue_depth_type & ~all_depth_types) |
	  !input->queue_depth_type))
    {
      inerror =
	format (inerror,
		" - ERROR: queue-depth-type must be - [drv-af-packet | drv-dpdk]\n");
    }
  u32 in_olen = *olen;
  u32 in_oid = *oid;
  if ((in_olen && in_oid)
      && (input->trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH))
    {
      u32 odata_len = vec_len (input->opaque.data);
      if (in_olen != odata_len)
	{
	  vlib_cli_output (vm,
			   "WARNING: opaque-len (%d) != len(opaque-data) (%d) octets - setting to (%d)",
			   in_olen, odata_len, odata_len);
	  in_olen = odata_len;
	}
      // round to 4 octet multiples
      in_olen = (in_olen + 3) & ~3;
      if (in_olen > IOAM_MAX_OPAQUE_DATA_BYTE_SIZE)
	{
	  vlib_cli_output (vm,
			   "WARNING: in_olen (%d) > max (%d) octets - using max length",
			   in_olen, IOAM_MAX_OPAQUE_DATA_BYTE_SIZE);
	  in_olen = IOAM_MAX_OPAQUE_DATA_BYTE_SIZE;
	}
      // lenght in 4 octet units
      in_olen = in_olen >> 2;
      input->opaque.len_schemeid = IOAM_SET_OPAQUE_HEADER (in_olen, in_oid);
    }
  else if (((!in_olen || !in_oid)
	    && (input->trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH))
	   || (!(input->trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH)
	       && (in_olen || in_oid)))
    {
      inerror =
	format (inerror,
		"ERROR: Opaque, check - opaque bit in trace-type (0x%x), opaque-len (%d) opaque-id (%d)",
		input->trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH, in_olen,
		in_oid);
    }
  return inerror;
}

/* *INDENT-ON* */
static clib_error_t *
set_trace_profile_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  trace_profile *profile = NULL;
  trace_profile user_defined;
  clib_memset (&user_defined, 0, sizeof (trace_profile));
  u32 olen = 0;
  u32 oid = 0;
  clear_trace_profiles ();
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "namespace-id %d", &user_defined.namespace_id));
      else if (unformat (input, "num-elts %d", &user_defined.num_elts));
      else
	if (unformat
	    (input, "node-id-short %d", &user_defined.node_id_short));
      else
	if (unformat
	    (input, "node-id-wide 0x%Lx", &user_defined.node_id_wide));
      else
	if (unformat
	    (input, "app-data-short 0x%x", &user_defined.app_data_short));
      else
	if (unformat
	    (input, "app-data-wide 0x%Lx", &user_defined.app_data_wide));
      else
	if (unformat
	    (input, "option-type %U", unformat_option_type,
	     &user_defined.option_type));
      else if (unformat (input, "trace-type 0x%x", &user_defined.trace_type));
      else
	if (unformat
	    (input, "node-type %U", unformat_node_type,
	     &user_defined.node_type));
      else
	if (unformat
	    (input, "ts-format-sub %U", unformat_ts_format,
	     &user_defined.ts_format));
      else
	if (unformat
	    (input, "queue-depth-type %U", unformat_queue_depth_format,
	     &user_defined.queue_depth_type));
      else if (unformat (input, "opaque-len %d", &olen));
      else if (unformat (input, "opaque-id %d", &oid));
      else
	if (unformat
	    (input, "opaque-data 0x%U", unformat_hex_string,
	     &user_defined.opaque.data));
      else
	break;
    }
  profile = trace_profile_find ();
  u8 *errstr = 0;
  errstr =
    format (errstr, "%U", trace_util_check_input, vm, &user_defined, &olen,
	    &oid);
  if (!errstr)
    {
      trace_profile_create (profile, &user_defined);
      show_trace_profile_command_fn (vm, input, cmd);
    }
  else
    {
      vec_free (user_defined.opaque.data);
      return clib_error_return (0, "%s", errstr);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_trace_profile_command, static) =
{
.path = "set ioam-trace profile",
.short_help = "set ioam-trace profile\n   Mandatory:\n      trace-type [as hex] namespace-id [n] num-elts [< 255] node-id-short [n > 0 (dec)] node-id-wide [n > 0x0 (hex)] queue-depth-type (if queue depth in trace-type) [drv-af-packet | drv-dpdk] node-type [encap | transit | decap]\n    Optional:\n     option-type [prealloc (default) | increment | pot | e2e] ts-format-sub [sec | ms | us | ns] app-data-short/-wide [in hex] opaque-len [n < 1020-bytes] opaque-id [n] opaque-data [hex]",
.function = set_trace_profile_command_fn,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
