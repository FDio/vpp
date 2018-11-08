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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip6.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <ioam/encap/ip6_ioam_pot.h>
#include <ioam/lib-pot/pot_util.h>

#define foreach_ip6_hop_by_hop_ioam_pot_stats				\
  _(PROCESSED, "Pkts with ip6 hop-by-hop pot options")			\
  _(PROFILE_MISS, "Pkts with ip6 hop-by-hop pot options but no profile set") \
  _(PASSED, "Pkts with POT in Policy")					\
  _(FAILED, "Pkts with POT out of Policy") 

static char * ip6_hop_by_hop_ioam_pot_stats_strings[] = {
#define _(sym,string) string,
  foreach_ip6_hop_by_hop_ioam_pot_stats
#undef _
};

typedef enum {
#define _(sym,str) IP6_IOAM_POT_##sym,
  foreach_ip6_hop_by_hop_ioam_pot_stats
#undef _
  IP6_IOAM_POT_N_STATS,
} ip6_ioam_pot_stats_t;

typedef struct {
  /* stats */
  u64 counters[ARRAY_LEN(ip6_hop_by_hop_ioam_pot_stats_strings)];
  
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip6_hop_by_hop_ioam_pot_main_t;

ip6_hop_by_hop_ioam_pot_main_t ip6_hop_by_hop_ioam_pot_main;

always_inline void 
ip6_ioam_stats_increment_counter (u32 counter_index, u64 increment)
{
  ip6_hop_by_hop_ioam_pot_main_t *hm = &ip6_hop_by_hop_ioam_pot_main;

  hm->counters[counter_index] += increment;
}


static u8 * format_ioam_pot (u8 * s, va_list * args)
{
  ioam_pot_option_t * pot0 = va_arg (*args, ioam_pot_option_t *);
  u64 random, cumulative;
  random = cumulative = 0;
  if (pot0) 
    { 
      random = clib_net_to_host_u64 (pot0->random);
      cumulative = clib_net_to_host_u64 (pot0->cumulative);
    }

  s = format (s, "random = 0x%Lx, Cumulative = 0x%Lx, Index = 0x%x", 
	      random, cumulative, pot0 ? pot0->reserved_profile_id : ~0);
  return s;
}

u8 *
ip6_hbh_ioam_proof_of_transit_trace_handler (u8 *s, ip6_hop_by_hop_option_t *opt)
{
  ioam_pot_option_t *pot;

  s = format (s, "    POT opt present\n");
  pot = (ioam_pot_option_t *) opt;
  s = format (s, "         %U\n", format_ioam_pot, pot);
  return (s);
}

int
ip6_hbh_ioam_proof_of_transit_handler (vlib_buffer_t *b,
				       ip6_header_t *ip,
				       ip6_hop_by_hop_option_t *opt0)
{
  ioam_pot_option_t * pot0;
  u64 random = 0, cumulative = 0;
  int rv = 0;
  u8 pot_profile_index;
  pot_profile *pot_profile = 0, *new_profile = 0;
  u8 pot_encap = 0;

  pot0 = (ioam_pot_option_t *) opt0;
  pot_encap = (pot0->random == 0);
  pot_profile_index = pot_profile_get_active_id();
  pot_profile = pot_profile_get_active();
  if (pot_encap && PREDICT_FALSE(!pot_profile))
    {
      ip6_ioam_stats_increment_counter (IP6_IOAM_POT_PROFILE_MISS, 1);
      return(-1);
    }
  if (pot_encap)
    {
      pot0->reserved_profile_id =
	pot_profile_index & PROFILE_ID_MASK;
      pot_profile_incr_usage_stats(pot_profile);
    } 
  else 
    { /* Non encap node */
      if (PREDICT_FALSE(pot0->reserved_profile_id != 
			pot_profile_index || pot_profile == 0)) 
	{
	  /* New profile announced by encap node. */
	  new_profile =
	    pot_profile_find(pot0->reserved_profile_id); 
	  if (PREDICT_FALSE(new_profile == 0 ||
			    new_profile->valid == 0)) 
	    {
	      ip6_ioam_stats_increment_counter (IP6_IOAM_POT_PROFILE_MISS, 1);
	      return(-1);
 	    } 
	  else 
	    {
	      pot_profile_index = pot0->reserved_profile_id;
	      pot_profile = new_profile;
	      pot_profile_set_active(pot_profile_index);
	      pot_profile_reset_usage_stats(pot_profile);
	    }
	}
      pot_profile_incr_usage_stats(pot_profile);
    }

  if (pot0->random == 0) 
    {
      pot0->random = clib_host_to_net_u64(pot_generate_random(pot_profile));
      pot0->cumulative = 0;
    }
  random = clib_net_to_host_u64(pot0->random);
  cumulative = clib_net_to_host_u64(pot0->cumulative);
  pot0->cumulative = clib_host_to_net_u64(
					  pot_update_cumulative(pot_profile,
								cumulative,
								random));
  ip6_ioam_stats_increment_counter (IP6_IOAM_POT_PROCESSED, 1);

  return (rv);
}

int
ip6_hbh_ioam_proof_of_transit_pop_handler (vlib_buffer_t *b, ip6_header_t *ip,
					   ip6_hop_by_hop_option_t *opt0)
{
  ioam_pot_option_t * pot0;
  u64 random = 0;
  u64 cumulative = 0;
  int rv = 0;
  pot_profile *pot_profile = 0;
  u8 result = 0;

  pot0 = (ioam_pot_option_t *) opt0;
  random = clib_net_to_host_u64(pot0->random);
  cumulative = clib_net_to_host_u64(pot0->cumulative);
  pot_profile = pot_profile_get_active();
  result =  pot_validate (pot_profile,
			  cumulative, random);

  if (result == 1)
    {
      ip6_ioam_stats_increment_counter (IP6_IOAM_POT_PASSED, 1);
    }
  else
    {
      ip6_ioam_stats_increment_counter (IP6_IOAM_POT_FAILED, 1);
    }
  return (rv);
}

int ip6_hop_by_hop_ioam_pot_rewrite_handler (u8 *rewrite_string, u8 *rewrite_size)
{
  ioam_pot_option_t * pot_option;
  if (rewrite_string && *rewrite_size == sizeof(ioam_pot_option_t))
    {
      pot_option = (ioam_pot_option_t *)rewrite_string;
      pot_option->hdr.type = HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT
        | HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
      pot_option->hdr.length = sizeof (ioam_pot_option_t) - 
        sizeof (ip6_hop_by_hop_option_t);
      return(0);
    }
  return(-1);
}

static clib_error_t *
ip6_show_ioam_pot_cmd_fn (vlib_main_t * vm,
			  unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  ip6_hop_by_hop_ioam_pot_main_t *hm = &ip6_hop_by_hop_ioam_pot_main;
  u8 *s = 0;
  int i = 0;

  for ( i = 0; i < IP6_IOAM_POT_N_STATS; i++)
    {
      s = format(s, " %s - %lu\n", ip6_hop_by_hop_ioam_pot_stats_strings[i],
	       hm->counters[i]);
    }

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}


VLIB_CLI_COMMAND (ip6_show_ioam_pot_cmd, static) = {
  .path = "show ioam pot",
  .short_help = "iOAM pot statistics",
  .function = ip6_show_ioam_pot_cmd_fn,
};


static clib_error_t *
ip6_hop_by_hop_ioam_pot_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_ioam_pot_main_t * hm = &ip6_hop_by_hop_ioam_pot_main;
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, ip6_hop_by_hop_ioam_init)))
    return(error);

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main();
  clib_memset(hm->counters, 0, sizeof(hm->counters));
  
  if (ip6_hbh_register_option(HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT, ip6_hbh_ioam_proof_of_transit_handler,
			      ip6_hbh_ioam_proof_of_transit_trace_handler) < 0)
    return (clib_error_create("registration of HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT failed"));

  if (ip6_hbh_add_register_option(HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT,
				  sizeof(ioam_pot_option_t),
				  ip6_hop_by_hop_ioam_pot_rewrite_handler) < 0)
    return (clib_error_create("registration of HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT for rewrite failed"));

  if (ip6_hbh_pop_register_option(HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT,
				  ip6_hbh_ioam_proof_of_transit_pop_handler) < 0)
    return (clib_error_create("registration of HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT POP failed"));

  return (0);
}

VLIB_INIT_FUNCTION (ip6_hop_by_hop_ioam_pot_init);


