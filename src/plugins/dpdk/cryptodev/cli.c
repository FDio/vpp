/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <dpdk/device/dpdk.h>

#include "cryptodev.h"

static u8 *
format_cryptodev_inst (u8 *s, va_list *args)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 inst = va_arg (*args, u32);
  cryptodev_inst_t *cit = cmt->cryptodev_inst + inst;
  clib_thread_index_t thread_index = 0;
  struct rte_cryptodev_info info;

  rte_cryptodev_info_get (cit->dev_id, &info);
  s = format (s, "%-25s%-10u", info.device->name, cit->q_id);

  vec_foreach_index (thread_index, cmt->per_thread_data)
    {
      cryptodev_engine_thread_t *cet = cmt->per_thread_data + thread_index;
      if (vlib_num_workers () > 0 && thread_index == 0)
	continue;

      if (cet->cryptodev_id == cit->dev_id && cet->cryptodev_q == cit->q_id)
	{
	  s = format (s, "%u (%v)\n", thread_index, vlib_worker_threads[thread_index].name);
	  break;
	}
    }

  if (thread_index == vec_len (cmt->per_thread_data))
    s = format (s, "%s\n", "free");

  return s;
}

static clib_error_t *
cryptodev_show_assignment_fn (vlib_main_t *vm, unformat_input_t *input __clib_unused,
			      vlib_cli_command_t *cmd __clib_unused)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  u32 inst;

  vlib_cli_output (vm, "%-5s%-25s%-10s%s\n", "No.", "Name", "Queue-id", "Assigned-to");
  if (vec_len (cmt->cryptodev_inst) == 0)
    {
      vlib_cli_output (vm, "(nil)\n");
      return 0;
    }

  vec_foreach_index (inst, cmt->cryptodev_inst)
    vlib_cli_output (vm, "%-5u%U", inst, format_cryptodev_inst, inst);

  if (cmt->is_raw_api)
    vlib_cli_output (vm, "Cryptodev Data Path API used: RAW Data Path API");
  else
    vlib_cli_output (vm, "Cryptodev Data Path API used: crypto operation API");
  return 0;
}

VLIB_CLI_COMMAND (show_cryptodev_assignment, static) = {
  .path = "show dpdk cryptodev assignment",
  .short_help = "show dpdk cryptodev assignment",
  .function = cryptodev_show_assignment_fn,
};

static clib_error_t *
cryptodev_show_cache_rings_fn (vlib_main_t *vm, unformat_input_t *input __clib_unused,
			       vlib_cli_command_t *cmd __clib_unused)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  clib_thread_index_t thread_index = 0;
  u16 i;

  vec_foreach_index (thread_index, cmt->per_thread_data)
    {
      cryptodev_engine_thread_t *cet = cmt->per_thread_data + thread_index;
      cryptodev_cache_ring_t *ring = &cet->cache_ring;
      u16 head = ring->head;
      u16 tail = ring->tail;
      u16 n_cached = (CRYPTODEV_CACHE_QUEUE_SIZE - tail + head) & CRYPTODEV_CACHE_QUEUE_MASK;
      u16 enq_head = ring->enq_head;
      u16 deq_tail = ring->deq_tail;
      u16 n_frames_inflight =
	(enq_head == deq_tail) ?
	  0 :
	  ((CRYPTODEV_CACHE_QUEUE_SIZE + enq_head - deq_tail) & CRYPTODEV_CACHE_QUEUE_MASK);
      u16 n_frames_processed =
	((tail == deq_tail) && (ring->frames[deq_tail].f == 0)) ?
	  0 :
	  ((CRYPTODEV_CACHE_QUEUE_SIZE - tail + deq_tail) & CRYPTODEV_CACHE_QUEUE_MASK) + 1;
      u16 n_frames_pending =
	(head == enq_head) ?
	  0 :
	  ((CRYPTODEV_CACHE_QUEUE_SIZE - enq_head + head) & CRYPTODEV_CACHE_QUEUE_MASK) - 1;
      u16 elts_to_enq = ring->frames[enq_head].n_elts - ring->frames[enq_head].enq_elts_head;
      u16 elts_to_deq = ring->frames[deq_tail].n_elts - ring->frames[deq_tail].deq_elts_tail;
      u32 elts_total = 0;

      for (i = 0; i < CRYPTODEV_CACHE_QUEUE_SIZE; i++)
	elts_total += ring->frames[i].n_elts;

      if (vlib_num_workers () > 0 && thread_index == 0)
	continue;

      vlib_cli_output (vm, "\n\n");
      vlib_cli_output (vm, "Frames cached in the ring: %u", n_cached);
      vlib_cli_output (vm, "Frames cached but not processed: %u", n_frames_pending);
      vlib_cli_output (vm, "Frames inflight: %u", n_frames_inflight);
      vlib_cli_output (vm, "Frames processed: %u", n_frames_processed);
      vlib_cli_output (vm, "Elements total: %u", elts_total);
      vlib_cli_output (vm, "Elements inflight: %u", cet->inflight);
      vlib_cli_output (vm, "Head index: %u", head);
      vlib_cli_output (vm, "Tail index: %u", tail);
      vlib_cli_output (vm, "Current frame index beeing enqueued: %u", enq_head);
      vlib_cli_output (vm, "Current frame index being dequeued: %u", deq_tail);
      vlib_cli_output (vm,
		       "Elements in current frame to be enqueued: %u, waiting "
		       "to be enqueued: %u",
		       ring->frames[enq_head].n_elts, elts_to_enq);
      vlib_cli_output (vm,
		       "Elements in current frame to be dequeued: %u, waiting "
		       "to be dequeued: %u",
		       ring->frames[deq_tail].n_elts, elts_to_deq);
      vlib_cli_output (vm, "\n\n");
    }

  return 0;
}

VLIB_CLI_COMMAND (show_cryptodev_sw_rings, static) = {
  .path = "show dpdk cryptodev cache status",
  .short_help = "show status of all dpdk cryptodev cache rings",
  .function = cryptodev_show_cache_rings_fn,
};

static u8 *
format_cryptodev_param_range (u8 *s, va_list *args)
{
  struct rte_crypto_param_range *r = va_arg (*args, struct rte_crypto_param_range *);

  if (r->increment == 0 || r->min == r->max)
    return format (s, "%u", r->min);

  return format (s, "%u-%u/%u", r->min, r->max, r->increment);
}

static void
cryptodev_show_capability (vlib_main_t *vm, const struct rte_cryptodev_capabilities *cap)
{
  const char *alg_name = 0;
  const char *xform_name = 0;

  if (cap->op == RTE_CRYPTO_OP_TYPE_SYMMETRIC)
    {
      switch (cap->sym.xform_type)
	{
	case RTE_CRYPTO_SYM_XFORM_AUTH:
	  alg_name = rte_cryptodev_get_auth_algo_string (cap->sym.auth.algo);
	  xform_name = "sym/auth";
	  vlib_cli_output (vm, "    %-8s %-24s block=%u key=%U digest=%U aad=%U iv=%U", xform_name,
			   alg_name ? alg_name : "unknown", cap->sym.auth.block_size,
			   format_cryptodev_param_range, &cap->sym.auth.key_size,
			   format_cryptodev_param_range, &cap->sym.auth.digest_size,
			   format_cryptodev_param_range, &cap->sym.auth.aad_size,
			   format_cryptodev_param_range, &cap->sym.auth.iv_size);
	  return;
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
	  alg_name = rte_cryptodev_get_cipher_algo_string (cap->sym.cipher.algo);
	  xform_name = "sym/cipher";
	  vlib_cli_output (vm, "    %-8s %-24s block=%u key=%U iv=%U dataunit=0x%x", xform_name,
			   alg_name ? alg_name : "unknown", cap->sym.cipher.block_size,
			   format_cryptodev_param_range, &cap->sym.cipher.key_size,
			   format_cryptodev_param_range, &cap->sym.cipher.iv_size,
			   cap->sym.cipher.dataunit_set);
	  return;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
	  alg_name = rte_cryptodev_get_aead_algo_string (cap->sym.aead.algo);
	  xform_name = "sym/aead";
	  vlib_cli_output (vm, "    %-8s %-24s block=%u key=%U digest=%U aad=%U iv=%U", xform_name,
			   alg_name ? alg_name : "unknown", cap->sym.aead.block_size,
			   format_cryptodev_param_range, &cap->sym.aead.key_size,
			   format_cryptodev_param_range, &cap->sym.aead.digest_size,
			   format_cryptodev_param_range, &cap->sym.aead.aad_size,
			   format_cryptodev_param_range, &cap->sym.aead.iv_size);
	  return;
	case RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED:
	  break;
	}

      vlib_cli_output (vm, "    sym      unknown-xform=%u", cap->sym.xform_type);
      return;
    }

  if (cap->op == RTE_CRYPTO_OP_TYPE_ASYMMETRIC)
    {
      xform_name = rte_cryptodev_asym_get_xform_string (cap->asym.xform_capa.xform_type);
      vlib_cli_output (vm, "    asym     %-24s op-types=0x%x hash-algos=0x%llx",
		       xform_name ? xform_name : "unknown", cap->asym.xform_capa.op_types,
		       cap->asym.xform_capa.hash_algos);
      return;
    }

  vlib_cli_output (vm, "    op=%u", cap->op);
}

static clib_error_t *
cryptodev_show_capabilities_fn (vlib_main_t *vm, unformat_input_t *input __clib_unused,
				vlib_cli_command_t *cmd __clib_unused)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *cit;
  const struct rte_cryptodev_capabilities *cap;
  struct rte_cryptodev_info info;
  u32 prev_dev_id = ~0;

  if (vec_len (cmt->cryptodev_inst) == 0)
    {
      vlib_cli_output (vm, "(nil)");
      return 0;
    }

  vec_foreach (cit, cmt->cryptodev_inst)
    {
      if (cit->dev_id == prev_dev_id)
	continue;

      prev_dev_id = cit->dev_id;
      rte_cryptodev_info_get (cit->dev_id, &info);

      vlib_cli_output (vm, "device %u: %s", cit->dev_id, info.device->name);
      vlib_cli_output (vm, "  driver: %s", info.driver_name);
      vlib_cli_output (vm, "  bus-info: %s",
		       info.device->bus_info ? info.device->bus_info : "(nil)");
      vlib_cli_output (vm, "  numa-node: %d", info.device->numa_node);
      vlib_cli_output (vm, "  queue-pairs: %u", info.max_nb_queue_pairs);
      vlib_cli_output (vm, "  symmetric: %s",
		       (info.feature_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) ? "yes" : "no");
      vlib_cli_output (vm, "  asymmetric: %s",
		       (info.feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO) ? "yes" : "no");
      vlib_cli_output (vm, "  raw-dp: %s",
		       (info.feature_flags & RTE_CRYPTODEV_FF_SYM_RAW_DP) ? "yes" : "no");
      vlib_cli_output (vm, "  capabilities:");

      for (cap = info.capabilities; cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; cap++)
	cryptodev_show_capability (vm, cap);

      vlib_cli_output (vm, "");
    }

  return 0;
}

VLIB_CLI_COMMAND (show_cryptodev_capabilities, static) = {
  .path = "show dpdk cryptodev capabilities",
  .short_help = "show dpdk cryptodev capabilities",
  .function = cryptodev_show_capabilities_fn,
};

static clib_error_t *
cryptodev_set_assignment_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd __clib_unused)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_thread_index_t thread_index, inst_index;
  u32 thread_present = 0, inst_present = 0;
  clib_error_t *error = 0;
  int ret;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "thread %u", &thread_index))
	thread_present = 1;
      else if (unformat (line_input, "resource %u", &inst_index))
	inst_present = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
    }

  if (!thread_present || !inst_present)
    return clib_error_return (0, "mandatory argument(s) missing");

  if (thread_index == 0 && vlib_num_workers () > 0)
    return clib_error_return (0, "assign crypto resource for master thread");

  if (thread_index > vec_len (cmt->per_thread_data) || inst_index > vec_len (cmt->cryptodev_inst))
    return clib_error_return (0, "wrong thread id or resource id");

  cet = cmt->per_thread_data + thread_index;
  ret = cryptodev_assign_resource (cet, inst_index, CRYPTODEV_RESOURCE_ASSIGN_UPDATE);
  if (ret)
    {
      error = clib_error_return (0, "cryptodev_assign_resource returned %d", ret);
      return error;
    }

  return 0;
}

VLIB_CLI_COMMAND (set_cryptodev_assignment, static) = {
  .path = "set dpdk cryptodev assignment",
  .short_help = "set dpdk cryptodev assignment thread <thread_index> resource <inst_index>",
  .function = cryptodev_set_assignment_fn,
};
