/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_output.h>

static clib_error_t *
test_ipsec_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  u64 seq_num;
  u32 sa_id;

  sa_id = ~0;
  seq_num = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sa %d", &sa_id))
	;
      else if (unformat (input, "seq 0x%llx", &seq_num))
	;
      else
	break;
    }

  if (~0 != sa_id)
    {
      ipsec_sa_t *sa;
      u32 sa_index;

      sa_index = ipsec_sa_find_and_lock (sa_id);
      sa = ipsec_sa_get (sa_index);

      sa->seq = seq_num & 0xffffffff;
      sa->seq_hi = seq_num >> 32;

      /* clear the window */
      if (ipsec_sa_is_set_ANTI_REPLAY_HUGE (sa))
	clib_bitmap_zero (sa->replay_window_huge);
      else
	sa->replay_window = 0;

      ipsec_sa_unlock (sa_index);
    }
  else
    {
      return clib_error_return (0, "unknown SA `%U'", format_unformat_error,
				input);
    }

  return (NULL);
}

static clib_error_t *
test_ipsec_spd_outbound_perf_command_fn (vlib_main_t *vm,
					 unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  ipsec_crypto_alg_t crypto_alg = IPSEC_CRYPTO_ALG_AES_GCM_128;
  ipsec_integ_alg_t integ_alg = IPSEC_INTEG_ALG_NONE;
  ipsec_protocol_t proto = IPSEC_PROTOCOL_ESP;
  ipsec_sa_flags_t sa_flags = IPSEC_SA_FLAG_NONE;
  ipsec_key_t ck = { 0 };
  u8 key_data[] = { 31, 32, 33, 34, 35, 36, 37, 38,
		    39, 30, 31, 32, 33, 34, 35, 36 };
  ipsec_mk_key (&ck, key_data, 16);
  ipsec_key_t ik = { 0 };
  u32 sa_id = 123456, spi = 654321, salt = 1234, sai;
  u16 udp_src = IPSEC_UDP_PORT_NONE, udp_dst = IPSEC_UDP_PORT_NONE;
  tunnel_t tun = {};

  /* SPD policy */
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p0 = NULL;
  ipsec_spd_t *spd0;
  uword *pp;
  u32 stat_index, spd_idx, spd_id = 1;
  int is_add = 1;
  int rv;
  ipsec_policy_t *p_vec = NULL;
  u64 i;
  u64 flows = 100;

  u64 t_add_0 = 0;
  u64 t_add_1 = 0;
  u64 t_add = 0;
  u64 t_look_0 = 0;
  u64 t_look_1 = 0;
  u64 t_look = 0;
  u8 flow_cache_enabled = im->output_flow_cache_flag;
  u32 count_cached = 0;
  u32 count_slow_path = 0;
  u32 seed = random_default_seed ();
  u32 *rand_val = NULL;
  u32 ip4_start;
#define BURST_MAX_SIZE 256
  ipsec_policy_t *policies[BURST_MAX_SIZE];
  ipsec4_spd_5tuple_t ip4_5tuples[BURST_MAX_SIZE];
  u32 burst_size = 10;
  int burst_enabled = 0;
  u64 t0 = clib_cpu_time_now ();
  u64 t1 = 0;
  u32 k = 0, m;
  u64 burst_counter = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "flows %d", &flows))
	;
      else if (unformat (input, "burst %d", &burst_size))
	{
	  if (burst_size == 0)
	    burst_enabled = 0;
	  else
	    {
	      burst_enabled = 1;
	      burst_size = clib_min (burst_size, BURST_MAX_SIZE);
	    }
	}
      else
	break;
    }

  vlib_cli_output (vm, "Create env:");
  /* creating a new SA */
  rv = ipsec_sa_add_and_lock (sa_id, spi, proto, crypto_alg, &ck, integ_alg,
			      &ik, sa_flags, clib_host_to_net_u32 (salt),
			      udp_src, udp_dst, 0, &tun, &sai);
  if (rv)
    {
      err = clib_error_return (0, "create sa failure");
      goto done;
    }
  else
    vlib_cli_output (vm, "\tAdd a new SA");

  /* creating a new SPD */
  rv = ipsec_add_del_spd (vm, spd_id, is_add);
  if (rv)
    {
      err = clib_error_return (0, "create spd failure");
      goto done;
    }
  else
    vlib_cli_output (vm, "\tAdd a new SPD");

  /* vector for spd_policy */
  vec_validate (p_vec, flows + 1);
  vec_validate (rand_val, flows + 1);

  /* fill spd policy */
  for (i = 0; i < flows; i++)
    {
      rand_val[i] = random_u32 (&seed) % flows;

      p_vec[i].type = IPSEC_SPD_POLICY_IP4_OUTBOUND;
      p_vec[i].priority = flows - i;
      p_vec[i].policy = IPSEC_POLICY_ACTION_PROTECT;
      p_vec[i].id = spd_id;
      p_vec[i].sa_id = sa_id;
      p_vec[i].protocol = IP_PROTOCOL_UDP;
      p_vec[i].lport.start = 1;
      p_vec[i].lport.stop = 1;
      p_vec[i].rport.start = 1;
      p_vec[i].rport.stop = 1;
      /* address: 1.0.0.0 as u32 */
      ip4_start = 16777216;
      p_vec[i].laddr.start.ip4.data_u32 =
	clib_host_to_net_u32 (ip4_start + i * 32);
      p_vec[i].laddr.stop.ip4.data_u32 =
	clib_host_to_net_u32 (ip4_start + i * 32);
      p_vec[i].raddr.start.ip4.data_u32 =
	clib_host_to_net_u32 (ip4_start + i * 32);
      p_vec[i].raddr.stop.ip4.data_u32 =
	clib_host_to_net_u32 (ip4_start + i * 32);
    }

  vlib_cli_output (vm, "Add SPD Policy");
  t_add_0 = clib_cpu_time_now ();
  for (i = 0; i < flows; i++)
    {
      rv = ipsec_add_del_policy (vm, &p_vec[i], is_add, &stat_index);
      if (rv)
	{
	  clib_warning ("No add SPD Policy: %u", stat_index);
	  err = clib_error_return (0, "add SPD Policy failure");
	  goto done;
	}
    }
  t_add_1 = clib_cpu_time_now ();

  pp = hash_get (im->spd_index_by_spd_id, spd_id);
  spd_idx = pp[0];
  spd0 = pool_elt_at_index (im->spds, spd_idx);

  vlib_cli_output (vm, "Lookup SPD Policy");
  u64 j = 0;
  u64 n_lookup = 1000 * 1000;
  t_look_0 = clib_cpu_time_now ();
  for (i = 0; i < n_lookup; i++)
    {
      if (flows == j)
	j = 0;

      p0 = NULL;
      if (flow_cache_enabled)
	{
	  p0 = ipsec4_out_spd_find_flow_cache_entry (
	    im, 0,
	    clib_net_to_host_u32 (ip4_start +
				  ((flows - 1) - rand_val[j]) * 32),
	    clib_net_to_host_u32 (ip4_start +
				  ((flows - 1) - rand_val[j]) * 32),
	    clib_net_to_host_u16 (1), clib_net_to_host_u16 (1));
	  if (p0)
	    count_cached++;
	}
      if (p0 == NULL)
	{
	  if (burst_enabled)
	    {
	      u32 src_addr = (ip4_start + ((flows - 1) - rand_val[j]) * 32);
	      u32 dst_addr = (ip4_start + ((flows - 1) - rand_val[j]) * 32);
	      ipsec4_spd_5tuple_t ip4_5tuple = {
		.ip4_addr = { (ip4_address_t) src_addr,
			      (ip4_address_t) dst_addr },
		.port = { 1, 1 },
		.proto = IP_PROTOCOL_UDP
	      };

	      if (k == burst_size)
		{
		  k = 0;
		  clib_memset (policies, 0,
			       burst_size * sizeof (ipsec_policy_t *));
		  burst_counter += ipsec_output_policy_match_n (
		    spd0, ip4_5tuples, policies, burst_size,
		    flow_cache_enabled);
		  for (m = 0; m < burst_size; m++)
		    {
		      ASSERT (policies[m] != 0);
		    }
		}

	      clib_memcpy (ip4_5tuples + k, &ip4_5tuple,
			   sizeof (ipsec4_spd_5tuple_t));
	      k++;
	    }
	  else
	    {

	      p0 = ipsec_output_policy_match (
		spd0, IP_PROTOCOL_UDP,
		(ip4_start + ((flows - 1) - rand_val[j]) * 32),
		(ip4_start + ((flows - 1) - rand_val[j]) * 32), 1, 1,
		flow_cache_enabled);
	    }

	  count_slow_path++;
	}
      j++;
      if (!burst_enabled)
	ASSERT (p0 != 0);
    }

  if (burst_enabled && k > 0)
    {
      clib_memset (policies, 0, k * sizeof (ipsec_policy_t *));
      burst_counter += ipsec_output_policy_match_n (
	spd0, ip4_5tuples, policies, k, flow_cache_enabled);
      for (m = 0; m < k; m++)
	{
	  ASSERT (policies[m] != 0);
	}
    }
  t_look_1 = clib_cpu_time_now ();

  t_add = (t_add_1 - t_add_0);
  t_look = (t_look_1 - t_look_0);

  vlib_cli_output (vm, "Results Outbound:");
  vlib_cli_output (vm, "Time to add %u flows: \t\t%12.10f s", flows,
		   (t_add / vm->clib_time.clocks_per_second));
  vlib_cli_output (vm, "Average time to add 1 flow: \t\t%12.10f s",
		   ((t_add / flows) / vm->clib_time.clocks_per_second));
  vlib_cli_output (vm, "Time to lookup %u flows: \t\t%12.10f s", flows,
		   (t_look / vm->clib_time.clocks_per_second));
  vlib_cli_output (vm, "Average time to lookup 1 flow: \t\t%12.10f s",
		   ((t_look / n_lookup) / vm->clib_time.clocks_per_second));

  vlib_cli_output (vm, " ");

  vlib_cli_output (vm, "Cycle CPU to add %u flows: \t\t%32lu cycles", flows,
		   t_add);
  vlib_cli_output (vm, "Average cycle CPU to add 1 flow: \t%32lu cycles",
		   t_add / flows);
  vlib_cli_output (vm, "Cycle CPU to lookup %u flows: \t%32lu cycles", flows,
		   t_look);
  vlib_cli_output (vm, "Average cycle CPU to lookup 1 flow: \t%32lu cycles",
		   t_look / n_lookup);

  if (count_slow_path || count_cached)
    vlib_cli_output (
      vm, "flow cache hit rate: \t\t%12.10f\n cached: \t%d\n slow_path: \t%d",
      ((float) count_cached) / ((float) count_cached + count_slow_path),
      count_cached, count_slow_path);

  if (burst_enabled)
    vlib_cli_output (vm, "Total number of packets matched in bursts: \t\t%d\n",
		     burst_counter);

done:
  vlib_cli_output (vm, "Cleaning:");
  /* delete SPD policy */
  is_add = 0;
  for (i = 0; i < flows; i++)
    {
      rv = ipsec_add_del_policy (vm, &p_vec[i], is_add, &stat_index);
      if (rv)
	{
	  clib_warning ("No delete SPD Policy: %u", i);
	  err = clib_error_return (0, "delete SPD Policy failure");
	}
    }
  vlib_cli_output (vm, "\tDelete all SPD Policy");

  /* delete SPD */
  rv = ipsec_add_del_spd (vm, spd_id, is_add);
  if (rv)
    {
      err = clib_error_return (0, "delete spd failure");
    }
  else
    vlib_cli_output (vm, "\tDelete SPD");

  /* delete SA */
  rv = ipsec_sa_unlock_id (sa_id);
  if (rv)
    {
      err = clib_error_return (0, "delete sa failure");
    }
  else
    vlib_cli_output (vm, "\tDelete SA");

  t1 = clib_cpu_time_now ();
  vlib_cli_output (vm, "Time for test: \t%12.10f s",
		   ((t1 - t0) / vm->clib_time.clocks_per_second));

  vec_free (p_vec);
  vlib_cli_output (vm, "End");

  return (err);
}

VLIB_CLI_COMMAND (test_ipsec_spd_perf_command, static) = {
  .path = "test ipsec_spd_outbound_perf",
  .short_help = "test ipsec_spd_outbound_perf flows <n_flows>",
  .function = test_ipsec_spd_outbound_perf_command_fn,
};

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_ipsec_command, static) = {
  .path = "test ipsec",
  .short_help = "test ipsec sa <ID> seq-num <VALUE>",
  .function = test_ipsec_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
