/*
 * hll.c - skeleton vpp engine plug-in
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
#include <hll/hll.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <math.h>

/* define message IDs */
#include <hll/hll_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <hll/hll_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <hll/hll_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <hll/hll_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <hll/hll_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE hmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

hll_main_t hll_main;

/* List of message types that this plugin understands */

#define foreach_hll_plugin_api_msg                           \
	_(HLL_ENABLE_DISABLE, hll_enable_disable)

/* Action function shared between message handler and debug CLI */

typedef struct
{
  vlib_main_t *vm;
  hll_list_t *hlls;
  hll_key_t *key_val0;
  u8 rel_out;
} hll_show_walk_ctx_t;



int
hll_enable_disable (hll_main_t * hmp, u32 sw_if_index, u32 multihll_size,
		    u32 size, u8 bits, u8 mode, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (hmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (hmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (enable_disable)
    {
      /* HLL init for sw_if_index */
      u32 index = vec_search (hmp->associated_sw_if_index, sw_if_index);
      if (index != ~0)
	{
	  clib_warning ("BUG: trying to apply twice hll on sw_if_index %d",
			sw_if_index);
	  return VNET_API_ERROR_INVALID_SW_IF_INDEX;
	}

      vec_validate (hmp->input_hll_vec_by_sw_if_index, sw_if_index);
      hll_list_t *hll_init_srcif = clib_mem_alloc (sizeof (hll_list_t));
      hmp->input_hll_vec_by_sw_if_index[sw_if_index] =
	(hll_list_t *) hll_init_srcif;

      vec_validate (hmp->hll_list_hash, sw_if_index);

      /* HT Creation */
      hmp->hll_list_hash_buckets = HLL_PLUGIN_HASH_BUCKETS;
      hmp->hll_list_hash_memory = HLL_PLUGIN_HASH_MEMORY;

      char *name = (char *) format (0, "HLL hash table-%d", sw_if_index);
      BV (clib_bihash_init) (&hmp->hll_list_hash[sw_if_index], name,
			     hmp->hll_list_hash_buckets,
			     hmp->hll_list_hash_memory);

      hll_init_srcif->hll_list_hash = &hmp->hll_list_hash[sw_if_index];

      /* HLL settings */
      hll_init_srcif->size = size;
      hll_init_srcif->size_asu64 = size / 8;
      hll_init_srcif->bits = bits;
      hll_init_srcif->multihll_size = multihll_size;
      hll_init_srcif->mode = mode;

      /* hll info array */
      hll_init_srcif->hll_info_vec = vec_new (hll_info_t, multihll_size);
      hll_init_srcif->hll_raw_count_vec = vec_new (u32, multihll_size);
      hll_init_srcif->hll_reg_count_vec = vec_new (u32, multihll_size);
      hll_init_srcif->hll_raw_est_vec = vec_new (double, multihll_size);
      hll_init_srcif->hll_raw_q_count_vec = vec_new (double, multihll_size);
      hll_init_srcif->reverse_hll_vec = vec_new (u32, multihll_size);

      hll_init_srcif->last_pkt_c = 0;

      /* HLL counters */
      hll_init_srcif->n_swaps = 0;
      hll_init_srcif->pkt_count = 0;
      hll_init_srcif->admittedaccess = 0;
      hll_init_srcif->deniedaccess = 0;


      /* create hll list */
      hll_init_srcif->hll_assigned = 0;
      hll_init_srcif->hllreg_vec =
	clib_mem_alloc (sizeof (u8 *) * multihll_size);
      for (int i = 0; i < multihll_size; i++)
	{
	  /* create '$size' substreams  */
	  u8 *registers = (u8 *) clib_mem_alloc (sizeof (u8) * size);
	  vec_validate (hll_init_srcif->hllreg_vec, i);
	  for (int j = 0; j < size; j++)
	    {
	      registers[j] = 0;
	    }
	  hll_init_srcif->hllreg_vec[i] = registers;
	  vec_validate (hll_init_srcif->hll_raw_count_vec, i);
	  hll_init_srcif->hll_raw_count_vec[i] = size;

	  vec_validate (hll_init_srcif->hll_reg_count_vec, i);
	  hll_init_srcif->hll_reg_count_vec[i] = 0;

	  vec_validate (hll_init_srcif->hll_raw_q_count_vec, i);
	  hll_init_srcif->hll_raw_q_count_vec[i] = size;

	  vec_validate (hll_init_srcif->hll_raw_est_vec, i);
	  hll_init_srcif->hll_raw_est_vec[i] = 0;

	  hll_info_t *hc_nfo =
	    (hll_info_t *) clib_mem_alloc (sizeof (hll_info_t));
	  vec_validate (hll_init_srcif->hll_info_vec, i);
	  hll_init_srcif->hll_info_vec[i] = hc_nfo;
	}


      /* save the associated sw_if_index */
      vec_add1 (hmp->associated_sw_if_index, sw_if_index);

      hll_create_periodic_process (hmp);

      vnet_feature_enable_disable ("device-input", "hll",
				   sw_if_index, enable_disable, 0, 0);
    }
  else
    {

      hll_create_periodic_process (hmp);

      vnet_feature_enable_disable ("device-input", "hll",
				   sw_if_index, enable_disable, 0, 0);

      /* HLL remove for sw_if_index */
      u32 index = vec_search (hmp->associated_sw_if_index, sw_if_index);
      if (index == ~0)
	{
	  clib_warning
	    ("BUG: trying to remove hll on a not associated sw_if_index %d",
	     sw_if_index);
	  return VNET_API_ERROR_INVALID_SW_IF_INDEX;
	}


      vec_del1 (hmp->associated_sw_if_index, index);
      clib_mem_free (hmp->input_hll_vec_by_sw_if_index[sw_if_index]);
    }


  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (hmp->vlib_main,
			     hmp->periodic_node_index,
			     HLL_EVENT_PERIODIC_ENABLE_DISABLE,
			     (uword) enable_disable);
  return rv;
}



/* The proposed method suffer of a large error variability if a single
 * memory element is used to store the maximum $\rho$ value . The HLL supersedes this limitation by:
 * i) dividing the input stream in ${2^m}$ substreams and associating a register to each substream,
 * and ii) performing the harmonic average among the results collected by the different ${M=2^m}$
 * substreams to estimate the cardinality (i.e. $E = \alpha_{m} M^2 Z^{-1}$, with $Z = (\sum_{j=1}^{M} 2^{-reg[j]})$).
 * The HLL can provide a relative accuracy (the standard error) in the order of  $1.04/\sqrt{2^m}$. */

/* this function computes the harmonic mean over the registers of a single hll-sketch */
double
hll_count (hll_list_t * hll, int index)
{
  double alpha_mm;
  u32 i;
  u8 *registers = (u8 *) hll->hllreg_vec[index];

  switch (hll->bits)
    {
    case 4:
      alpha_mm = 0.673;
      break;
    case 5:
      alpha_mm = 0.697;
      break;
    case 6:
      alpha_mm = 0.709;
      break;
    default:
      alpha_mm = 0.7213 / (1.0 + 1.079 / (double) hll->size);
      break;
    }

  alpha_mm *= ((double) hll->size * (double) hll->size);

  double sum = 0;
  for (i = 0; i < hll->size; i++)
    {
      sum += 1.0 / (1 << registers[i]);
    }

  double estimate = alpha_mm / sum;

  if (estimate <= 5.0 / 2.0 * (double) hll->size)
    {
      int zeros = 0;

      for (i = 0; i < hll->size; i++)
	zeros += (registers[i] == 0);

      if (zeros)
	estimate = (double) hll->size * log ((double) hll->size / zeros);

    }
  else if (estimate > (1.0 / 30.0) * 4294967296.0)
    {
      estimate = -4294967296.0 * log (1.0 - (estimate / 4294967296.0));
    }

  return estimate;
}

/* compute the cardinality estimation for each hll-sketch allocated*/
static void
count_hll_ht (const clib_bihash_kv_16_8_t * kvp, void *args)
{
  hll_show_walk_ctx_t *ctx = args;
  vlib_main_t *vm;
  vm = ctx->vm;

  hll_list_t *hlls;
  hlls = ctx->hlls;

  ip46_address_t key = { };
  hll_key_t *key_val0 = (hll_key_t *) & kvp->key;
  hll_value_t *result_val0 = (hll_value_t *) & kvp->value;

  ctx->key_val0 = key_val0;

  if (hlls->mode == 1 || hlls->mode == 3)
    {
      key.ip4.as_u32 = key_val0->src_address;
    }
  if (hlls->mode == 2 || hlls->mode == 4)
    {
      key.ip4.as_u32 = key_val0->dst_address;
      key.ip4.as_u32 = key_val0->src_address;
    }



  u32 hll_index = result_val0->hll_index;

  hll_info_t *hll_info = (hll_info_t *) hlls->hll_info_vec[hll_index];
  u32 raw_count_index = hll_info->raw_count_index;
  u32 raw_count_value = hlls->hll_raw_count_vec[raw_count_index];
  double raw_q_count_value = hlls->hll_raw_q_count_vec[raw_count_index];
  u32 reg_count_value = hlls->hll_reg_count_vec[raw_count_index];

  u8 max_value = 0;
  u8 *registers = (u8 *) hlls->hllreg_vec[hll_index];
  for (int j = 0; j < hlls->size; j++)
    {
      if (registers[j] > max_value)
	max_value = registers[j];
    }

  double estimate = hlls->hll_raw_est_vec[raw_count_index];
  double estimate_hll = hll_count (hlls, hll_index);
  if (raw_count_index >= (RELEGATION_SPOT + INTERMEDIATE_ZONE)
      && !ctx->rel_out)
    vlib_cli_output (vm,
		     "%9.2f \t %U    \t %9.2f \t %9.2f \t %04d \t %10d \t %10d \t %d",
		     estimate, format_ip46_address, &key, IP46_TYPE_IP4,
		     estimate_hll, raw_q_count_value, raw_count_index,
		     raw_count_value, reg_count_value, max_value);

  else if (raw_count_index < (RELEGATION_SPOT + INTERMEDIATE_ZONE)
	   && ctx->rel_out)
    vlib_cli_output (vm,
		     "%9.2f \t %U    \t %9.2f \t %9.2f \t %04d \t %10d \t %10d \t %d",
		     estimate, format_ip46_address, &key, IP46_TYPE_IP4,
		     estimate_hll, raw_q_count_value, raw_count_index,
		     raw_count_value, reg_count_value, max_value);

}

/* VPP-CLI to trigger count */

static clib_error_t *
hll_count_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  hll_main_t *hmp = &hll_main;

  int i = 0;
  for (i = 0; i < vec_len (hmp->associated_sw_if_index); i++)
    {
      vlib_cli_output (vm, "--------------------------------------");

      hll_list_t *hlls =
	(hll_list_t *) hmp->
	input_hll_vec_by_sw_if_index[hmp->associated_sw_if_index[i]];
      vlib_cli_output (vm, "sw_if_index: %d | bits: %d | size: %d | mode: %d",
		       hmp->associated_sw_if_index[i], hlls->bits, hlls->size,
		       hlls->mode);
      vlib_cli_output (vm,
		       "pkt_count: %d | admitted times: %d (%.3f) | not_monitored: %d (%.3f)",
		       hlls->pkt_count, hlls->admittedaccess,
		       (hlls->admittedaccess / (hlls->pkt_count + 1.0)),
		       hlls->deniedaccess,
		       (hlls->deniedaccess / (hlls->pkt_count + 1.0)));
      vlib_cli_output (vm, "raw_count swaps: %d ", hlls->n_swaps);
      vlib_cli_output (vm, "hll_assigned: %d (%d)", hlls->hll_assigned,
		       hlls->multihll_size);


      vlib_cli_output (vm, "--------------------------------------");
      vlib_cli_output (vm,
		       "< val > \t < key > \t Hll_count \t stream_q \t raw_count_index \t raw_count_value \t reg_count_value \t max_reg_value ");
      vlib_cli_output (vm, "--------------------------------------");

      hll_show_walk_ctx_t ctx = {
	.vm = vm,
	.hlls = hlls,
	.key_val0 = 0,
	.rel_out = 1,
      };

      BV (clib_bihash_foreach_key_value_pair) (hlls->hll_list_hash,
					       count_hll_ht, &ctx);
      vlib_cli_output (vm, "==========Top-K zone=============");

      ctx.rel_out = 0;

      BV (clib_bihash_foreach_key_value_pair) (hlls->hll_list_hash,
					       count_hll_ht, &ctx);
      vlib_cli_output (vm, "=========================");
    }

  return 0;
}

/* show the entire sketch for each hll-sketch allocated */
static void
walk_hll_ht (const clib_bihash_kv_16_8_t * kvp, void *args)
{
  hll_show_walk_ctx_t *ctx = args;
  vlib_main_t *vm;
  vm = ctx->vm;

  hll_list_t *hlls;
  hlls = ctx->hlls;

  ip46_address_t key = { };
  hll_key_t *key_val0 = (hll_key_t *) & kvp->key;
  hll_value_t *result_val0 = (hll_value_t *) & kvp->value;

  u32 hll_index = result_val0->hll_index;

  vlib_cli_output (vm, "======================================");
  if (hlls->mode == 1 || hlls->mode == 3)
    {
      key.ip4.as_u32 = key_val0->src_address;
    }
  if (hlls->mode == 2 || hlls->mode == 4)
    {
      key.ip4.as_u32 = key_val0->dst_address;
      key.ip4.as_u32 = key_val0->src_address;
    }
  vlib_cli_output (vm, "key: %U", format_ip46_address, &key, IP46_TYPE_IP4);
  vlib_cli_output (vm, "-------------------------------------");

  u32 raw_count = 0;
  u8 *s = 0;
  u8 *registers = (u8 *) hlls->hllreg_vec[hll_index];
  for (int j = 0; j < hlls->size; j++)
    {
      raw_count = raw_count + (1 << registers[j]);
      s = format (s, "%02x ", registers[j], 1);
    }

  vlib_cli_output (vm, "%v", s);
  vlib_cli_output (vm, "Rough counter: %d", raw_count);



}

/* VPP-CLI to show the hll sketch */
static clib_error_t *
hll_show_counter_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  hll_main_t *hmp = &hll_main;

  u32 count;

  count = hmp->counter;

  vlib_cli_output (vm, "I counted %d pkts", count);

  int i = 0;
  for (i = 0; i < vec_len (hmp->associated_sw_if_index); i++)
    {
      vlib_cli_output (vm, "--------------------------------------");

      hll_list_t *hlls =
	(hll_list_t *) hmp->
	input_hll_vec_by_sw_if_index[hmp->associated_sw_if_index[i]];
      vlib_cli_output (vm,
		       "sw_if_index: %d | bits: %d | size: %d | mode: %d ",
		       hmp->associated_sw_if_index[i], hlls->bits, hlls->size,
		       hlls->mode);
      vlib_cli_output (vm,
		       "pkt_count: %d | admitted times: %d (%.3f) | not_monitored: %d (%.3f)",
		       hlls->pkt_count, hlls->admittedaccess,
		       (hlls->admittedaccess / (hlls->pkt_count + 1.0)),
		       hlls->deniedaccess,
		       (hlls->deniedaccess / (hlls->pkt_count + 1.0)));
      vlib_cli_output (vm, "\nhash table:\n%U\n", BV (format_bihash),
		       hlls->hll_list_hash, 1);

      vlib_cli_output (vm, "hll_assigned: %d (%d)", hlls->hll_assigned,
		       hlls->multihll_size);

      hll_show_walk_ctx_t ctx = {
	.vm = vm,
	.hlls = hlls,
      };

      BV (clib_bihash_foreach_key_value_pair) (hlls->hll_list_hash,
					       walk_hll_ht, &ctx);

    }

  return 0;
}

static clib_error_t *
hll_reset_counter_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  hll_main_t *hmp = &hll_main;

  int i = 0, j = 0;
  int hll_index = 0;
  for (i = 0; i < vec_len (hmp->associated_sw_if_index); i++)
    {
      hll_list_t *hlls =
	(hll_list_t *) hmp->
	input_hll_vec_by_sw_if_index[hmp->associated_sw_if_index[i]];
      for (hll_index = 0; hll_index < hlls->hll_assigned; hll_index++)
	{
	  u64 *registers = (u64 *) hlls->hllreg_vec[hll_index];
	  for (j = 0; j < hlls->size_asu64; j = j + 2)
	    {
	      registers[j] = (u64) 0;
	      registers[j + 1] = (u64) 0;
	    }
	}
    }

  hll_show_counter_command_fn (vm, input, cmd);

  return 0;
}

/* VPP-CLI to assign an hll to an interface */
static clib_error_t *
hll_start_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  hll_main_t *hmp = &hll_main;
  u32 sw_if_index = ~0;
  u8 bits = 5;
  u32 size = 32;
  u8 mode = 1;
  u32 tmp_val;
  u32 multihll_size = RELEGATION_SPOT + 1;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "multi %d", &tmp_val))
	{
	  multihll_size = tmp_val;
	}
      /* mode provides the capability of run-time selection of the packet fields used to
       * identify the flow (the plugin allocates a HLL for each flow)
       * and to discriminate distinct elements (i.e. to count the unique occurrence inside the stream). */
      else if (unformat (input, "mode %d", &tmp_val))
	{
	  mode = tmp_val;
	}
      else if (unformat (input, "bits %d", &tmp_val))
	{
	  bits = tmp_val;
	  size = (u32) 1 << bits;
	}
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 hmp->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  multihll_size = multihll_size + RELEGATION_SPOT + INTERMEDIATE_ZONE;
  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
  if (bits < 4 && bits > 32)
    return clib_error_return (0, "Please specify bits in the interval 4-32");


  rv =
    hll_enable_disable (hmp, sw_if_index, multihll_size, size, bits, mode,
			enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "hll_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hll_start_command, static) =
{
	.path = "hll start",
	.short_help =
		"hll start <interface-name> [multi <number of perflow_hll>] [bits <number of substreams>] [disable]",
	.function = hll_start_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hll_count_command, static) =
{
	.path = "hll count",
	.short_help =
		"hll count",
	.function = hll_count_command_fn,
};
VLIB_CLI_COMMAND (hll_show_counter_command, static) =
{
	.path = "hll show-counter",
	.short_help =
		"hll show-counter",
	.function = hll_show_counter_command_fn,
};
VLIB_CLI_COMMAND (hll_reset_counter_command, static) =
{
	.path = "hll reset-counter",
	.short_help =
		"hll reset-counter",
	.function = hll_reset_counter_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_hll_enable_disable_t_handler
  (vl_api_hll_enable_disable_t * mp)
{
  vl_api_hll_enable_disable_reply_t *rmp;
  hll_main_t *hmp = &hll_main;
  int rv;

  rv = hll_enable_disable (hmp, ntohl (mp->sw_if_index), 10, 32, 5, 1,
			   (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_HLL_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
hll_plugin_api_hookup (vlib_main_t * vm)
{
  hll_main_t *hmp = &hll_main;
#define _(N,n)                                                  \
	vl_msg_api_set_handlers((VL_API_##N + hmp->msg_id_base),     \
#n,					\
vl_api_##n##_t_handler,              \
vl_noop_handler,                     \
vl_api_##n##_t_endian,               \
vl_api_##n##_t_print,                \
sizeof(vl_api_##n##_t), 1);
  foreach_hll_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <hll/hll_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (hll_main_t * hmp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + hmp->msg_id_base);
  foreach_vl_msg_name_crc_hll;
#undef _
}

static clib_error_t *
hll_init (vlib_main_t * vm)
{
  hll_main_t *hmp = &hll_main;
  clib_error_t *error = 0;
  u8 *name;

  hmp->vlib_main = vm;
  hmp->vnet_main = vnet_get_main ();

  name = format (0, "hll_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  hmp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = hll_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (hmp, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (hll_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (hll, static) =
{
	.arc_name = "device-input",
	.node_name = "hll",
	.runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
	.version = VPP_BUILD_VER,
	.description = "hll plugin a stream based monitor tool",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
