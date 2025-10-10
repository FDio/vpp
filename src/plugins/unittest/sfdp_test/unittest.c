/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <vnet/plugin/plugin.h>
#include <unittest/sfdp_test/unittest.h>
#include <unittest/unity/unity.h>

void
setUp (void)
{
}

void
tearDown (void)
{
}

void
sfdp_setUp (void)
{
  /* Create a sfdp tenant */
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_bitmap_t bmp = 0;
  bmp |= SFDP_SERVICE_MASK (unittest);
  bmp |= SFDP_SERVICE_MASK (drop);

  sfdp_tenant_add_del (sfdp, 0, 0, 0);
  /* Set a trivial service chain */
  sfdp_set_services (sfdp, 0, bmp, SFDP_FLOW_FORWARD);
  sfdp_set_services (sfdp, 0, bmp, SFDP_FLOW_REVERSE);
}

void
sfdp_tearDown (void)
{
  /* Remove the sfdp tenant (not well handled for now)*/
  /* sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_add_del (sfdp, 0, 0, 1);
  */
}

void test_parser_v4_fn (void);

static clib_error_t *
sfdp_run_unit_tests (void)
{
  clib_error_t *error = 0;
  UNITY_BEGIN ();
  sfdp_setUp ();
  RUN_TEST (test_parser_v4_fn);
  sfdp_tearDown ();
  UNITY_END ();

  return error;
}

static clib_error_t *
sfdp_unittest_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  unformat_user (input, unformat_line_input, line_input);

  return sfdp_run_unit_tests ();
}

VLIB_NODE_FN (sfdp_unittest_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_unittest_main_t *um = &sfdp_unittest_main;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame), *bi = from;
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  sfdp_unittest_pending_pkt_t *pending_pkt;
  vlib_get_buffers (vm, from, bufs, n_left);

  ASSERT (vlib_get_thread_index () == 0);
  b = bufs;

  while (n_left)
    {
      sfdp_next (b[0], current_next);
      uword *pending_pkt_idx = hash_get (um->pending_pkts_by_bi, bi[0]);
      u32 *enq;
      if (pending_pkt_idx)
	{
	  pending_pkt =
	    pool_elt_at_index (um->pending_pkts, pending_pkt_idx[0]);
	  pending_pkt->success =
	    pending_pkt->test_cb (pending_pkt, pending_pkt->test_data);

	  enq = clib_ring_enq (um->handled_pkts);

	  if (enq)
	    enq[0] = pending_pkt_idx[0];

	  /* Remove bi from hash */
	  hash_unset (um->pending_pkts_by_bi, bi[0]);
	}
      bi += 1;
      current_next += 1;
      b += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

static clib_error_t *
sfdp_unittest_init (vlib_main_t *vm)
{
  clib_error_t *err = 0;
  sfdp_unittest_main_t *um = &sfdp_unittest_main;

  clib_ring_new (um->handled_pkts, SFDP_UNITTEST_MAX_PENDING_PKTS);
  um->pending_pkts_by_bi = hash_create (0, sizeof (uword));

  return err;
}

VLIB_CLI_COMMAND (sfdp_unittest_command, static) = {
  .path = "test sfdp",
  .short_help = "Run sfdp unit tests",
  .function = sfdp_unittest_command_fn,
};

VLIB_REGISTER_NODE (sfdp_unittest_node) = {
  .name = "sfdp-unittest",
  .vector_size = sizeof (u32),
  .format_trace = 0,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .error_strings = NULL,
};

SFDP_SERVICE_DEFINE (unittest) = {
  .node_name = "sfdp-unittest",
  .runs_before = SFDP_SERVICES ("sfdp-drop"),
  .runs_after = SFDP_SERVICES (0),
  .is_terminal = 0,
};

VLIB_INIT_FUNCTION (sfdp_unittest_init);

#ifndef CLIB_MARCH_VARIANT
sfdp_unittest_main_t sfdp_unittest_main;
u8 *_sfdp_unittest_pending_output;
#endif