/*
 * ct6.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/plugin/plugin.h>
#include <ct6/ct6.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <ct6/ct6_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ct6/ct6_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ct6/ct6_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ct6/ct6_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ct6/ct6_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE cmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

ct6_main_t ct6_main;

/* List of message types that this plugin understands */

#define foreach_ct6_plugin_api_msg                           \
_(CT6_ENABLE_DISABLE, ct6_enable_disable)

/* Action function shared between message handler and debug CLI */

static void
ct6_feature_init (ct6_main_t * cmp)
{
  u32 nworkers = vlib_num_workers ();

  if (cmp->feature_initialized)
    return;

  clib_bihash_init_48_8 (&cmp->session_hash, "ct6 session table",
			 cmp->session_hash_buckets, cmp->session_hash_memory);
  cmp->feature_initialized = 1;
  vec_validate (cmp->sessions, nworkers);
  vec_validate_init_empty (cmp->first_index, nworkers, ~0);
  vec_validate_init_empty (cmp->last_index, nworkers, ~0);
}

int
ct6_in2out_enable_disable (ct6_main_t * cmp, u32 sw_if_index,
			   int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  ct6_feature_init (cmp);

  /* Utterly wrong? */
  if (pool_is_free_index (cmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (cmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("interface-output", "ct6-in2out",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

int
ct6_out2in_enable_disable (ct6_main_t * cmp, u32 sw_if_index,
			   int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  ct6_feature_init (cmp);

  /* Utterly wrong? */
  if (pool_is_free_index (cmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (cmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("ip6-unicast", "ct6-out2in",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
set_ct6_enable_disable_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  ct6_main_t *cmp = &ct6_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  u32 inside = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 cmp->vnet_main, &sw_if_index))
	;
      else if (unformat (input, "inside") || unformat (input, "in"))
	inside = 1;
      else if (unformat (input, "outside") || unformat (input, "out"))
	inside = 0;
      else
	break;
    }

  if (inside == ~0)
    return clib_error_return (0, "Please specify inside or outside");

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (inside == 1)
    rv = ct6_in2out_enable_disable (cmp, sw_if_index, enable_disable);
  else
    rv = ct6_out2in_enable_disable (cmp, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    default:
      return clib_error_return (0, "ct6_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ct6_command, static) =
{
  .path = "set ct6",
  .short_help =
  "set ct6 [inside|outside] <interface-name> [disable]",
  .function = set_ct6_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_ct6_enable_disable_t_handler
  (vl_api_ct6_enable_disable_t * mp)
{
  vl_api_ct6_enable_disable_reply_t *rmp;
  ct6_main_t *cmp = &ct6_main;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_inside)
    rv = ct6_in2out_enable_disable (cmp, ntohl (mp->sw_if_index),
				    (int) (mp->enable_disable));
  else
    rv = ct6_out2in_enable_disable (cmp, ntohl (mp->sw_if_index),
				    (int) (mp->enable_disable));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_CT6_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
ct6_plugin_api_hookup (vlib_main_t * vm)
{
  ct6_main_t *cmp = &ct6_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + cmp->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ct6_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ct6/ct6_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ct6_main_t * cmp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + cmp->msg_id_base);
  foreach_vl_msg_name_crc_ct6;
#undef _
}

static clib_error_t *
ct6_init (vlib_main_t * vm)
{
  ct6_main_t *cmp = &ct6_main;
  clib_error_t *error = 0;
  u8 *name;

  cmp->vlib_main = vm;
  cmp->vnet_main = vnet_get_main ();

  name = format (0, "ct6_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  cmp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = ct6_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (cmp, &api_main);

  vec_free (name);

  /*
   * Set default parameters...
   * 256K sessions
   * 64K buckets
   * 2 minute inactivity timer
   * 10000 concurrent sessions
   */
  cmp->session_hash_memory = 16ULL << 20;
  cmp->session_hash_buckets = 64 << 10;
  cmp->session_timeout_interval = 120.0;
  cmp->max_sessions_per_worker = 10000;

  /* ... so the packet generator can feed the in2out node ... */
  ethernet_setup_node (vm, ct6_in2out_node.index);
  return error;
}

VLIB_INIT_FUNCTION (ct6_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ct6out2in, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ct6-out2in",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ct6in2out, static) =
{
  .arc_name = "interface-output",
  .node_name = "ct6-in2out",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "ipv6 connection tracker",
};
/* *INDENT-ON* */

u8 *
format_ct6_session (u8 * s, va_list * args)
{
  ct6_main_t *cmp = va_arg (*args, ct6_main_t *);
  int i = va_arg (*args, int);
  ct6_session_t *s0 = va_arg (*args, ct6_session_t *);
  int verbose = va_arg (*args, int);
  clib_bihash_kv_48_8_t kvp0;

  if (s0 == 0)
    {
      s = format (s, "\n%6s%6s%40s%6s%40s%6s",
		  "Sess", "Prot", "Src", "Sport", "Dst", "Dport");
      return s;
    }

  s = format (s, "\n%6d%6d%40U%6u%40U%6u",
	      s0 - cmp->sessions[i], s0->key.proto,
	      format_ip6_address, &s0->key.src,
	      clib_net_to_host_u16 (s0->key.sport),
	      format_ip6_address, &s0->key.dst,
	      clib_net_to_host_u16 (s0->key.dport));

  clib_memcpy_fast (&kvp0, s0, sizeof (ct6_session_key_t));

  if (clib_bihash_search_48_8 (&cmp->session_hash, &kvp0, &kvp0) < 0)
    {
      s = format (s, " LOOKUP FAIL!");
    }
  else
    {
      if (kvp0.value == s0 - cmp->sessions[s0->thread_index])
	{
	  s = format (s, " OK");
	  if (verbose > 1)
	    {
	      s = format (s, " next %d prev %d", s0->next_index,
			  s0->prev_index);
	      s = format (s, " hits %d expires %.2f", s0->hits, s0->expires);
	    }
	}
      else
	s = format (s, " BOGUS LOOKUP RESULT!");
    }

  return s;
}

static clib_error_t *
show_ct6_command_fn_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  ct6_main_t *cmp = &ct6_main;
  ct6_session_t *s0;
  int verbose = 0;
  u8 *s = 0;
  int i;

  if (!cmp->feature_initialized)
    return clib_error_return (0, "ip6 connection tracking not enabled...");

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

  for (i = 0; i < vec_len (cmp->sessions); i++)
    {
      s = format (s, "Thread %d: %d sessions\n", i,
		  pool_elts (cmp->sessions[i]));

      if (verbose == 0)
	continue;

      s =
	format (s, "%U", format_ct6_session, cmp,
		0 /* pool */ , 0 /* header */ , verbose);

      /* *INDENT-OFF* */
      pool_foreach (s0, cmp->sessions[i],
      ({
        s = format (s, "%U", format_ct6_session, cmp, i, s0, verbose);
      }));
      /* *INDENT-ON* */
    }
  vlib_cli_output (cmp->vlib_main, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ct6_command_fn_command, static) =
{
  .path = "show ip6 connection-tracker",
  .short_help = "show ip6 connection-tracker",
  .function = show_ct6_command_fn_command_fn,
};
/* *INDENT-ON* */

static void
increment_v6_address (ip6_address_t * a)
{
  u64 v0, v1;

  v0 = clib_net_to_host_u64 (a->as_u64[0]);
  v1 = clib_net_to_host_u64 (a->as_u64[1]);

  v1 += 1;
  if (v1 == 0)
    v0 += 1;
  a->as_u64[0] = clib_net_to_host_u64 (v0);
  a->as_u64[1] = clib_net_to_host_u64 (v1);
}


static clib_error_t *
test_ct6_command_fn_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  ct6_main_t *cmp = &ct6_main;
  clib_bihash_kv_48_8_t kvp0;
  ct6_session_key_t *key0;
  ct6_session_t *s0;
  u8 src[16], dst[16];
  u32 recycled = 0, created = 0;
  int i, num_sessions = 5;
  u32 midpt_index;
  u8 *s = 0;

  cmp->max_sessions_per_worker = 4;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "num-sessions %d", &num_sessions))
	;
      else
	if (unformat
	    (input, "max-sessions %d", &cmp->max_sessions_per_worker))
	;
      else
	break;
    }

  ct6_feature_init (cmp);

  /* Set up starting src/dst addresses */
  memset (src, 0, sizeof (src));
  memset (dst, 0, sizeof (dst));

  src[0] = 0xdb;
  dst[0] = 0xbe;

  src[15] = 1;
  dst[15] = 1;

  /*
   * See if we know about this flow.
   * Key set up for the out2in path, the performant case
   */
  key0 = (ct6_session_key_t *) & kvp0;
  memset (&kvp0, 0, sizeof (kvp0));

  for (i = 0; i < num_sessions; i++)
    {
      clib_memcpy_fast (&key0->src, src, sizeof (src));
      clib_memcpy_fast (&key0->dst, dst, sizeof (dst));
      key0->as_u64[4] = 0;
      key0->as_u64[5] = 0;
      key0->sport = clib_host_to_net_u16 (1234);
      key0->dport = clib_host_to_net_u16 (4321);
      key0->proto = 17;		/* udp, fwiw */

      s0 = ct6_create_or_recycle_session
	(cmp, &kvp0, 3.0 /* now */ , 0 /* thread index */ ,
	 &recycled, &created);

      s = format (s, "%U (%d, %d)", format_ct6_session, cmp,
		  0 /* thread index */ , s0, 1 /* verbose */ ,
		  recycled, created);
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      increment_v6_address ((ip6_address_t *) src);
      recycled = 0;
      created = 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (s0, cmp->sessions[0],
  ({
    s = format (s, "%U", format_ct6_session, cmp, 0, s0, 1 /* verbose */);
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "\nEnd state: first index %d last index %d\n%v",
		   cmp->first_index[0], cmp->last_index[0], s);

  vec_free (s);

  midpt_index = cmp->max_sessions_per_worker / 3;

  s0 = pool_elt_at_index (cmp->sessions[0], midpt_index);
  vlib_cli_output (vm, "\nSimulate LRU hit on session %d",
		   s0 - cmp->sessions[0]);

  ct6_update_session_hit (cmp, s0, 234.0);

  /* *INDENT-OFF* */
  pool_foreach (s0, cmp->sessions[0],
  ({
    s = format (s, "%U", format_ct6_session, cmp, 0, s0, 1 /* verbose */);
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "\nEnd state: first index %d last index %d\n%v",
		   cmp->first_index[0], cmp->last_index[0], s);

  vec_free (s);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_ct6_command_fn_command, static) =
{
  .path = "test ip6 connection-tracker",
  .short_help = "test ip6 connection-tracker",
  .function = test_ct6_command_fn_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ct6_config (vlib_main_t * vm, unformat_input_t * input)
{
  ct6_main_t *cmp = &ct6_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "session-hash-buckets %u",
		    &cmp->session_hash_buckets))
	;
      else if (unformat (input, "session-hash-memory %U",
			 unformat_memory_size, &cmp->session_hash_memory))
	;
      else if (unformat (input, "session-timeout %f",
			 &cmp->session_timeout_interval))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (ct6_config, "ct6");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
