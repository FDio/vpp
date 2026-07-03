/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/adj/adj.h>
#include <vnet/bfd/bfd_vnet_notifier.h>
#include <vnet/ethernet/ethernet.h>

// clang-format off

static int adj_test_do_debug;

#define ADJ_TEST_ALL_CASES 0
#define ADJ_TEST_POSITIVE_CASES 1
#define ADJ_TEST_NEGATIVE_CASES 2
#define ADJ_TEST_DUPLICASTE_CASES 3

#define ADJ_TEST_I(_cond, _comment, _args...)                                                      \
  ({                                                                                               \
    int _evald = (_cond);                                                                          \
    if (!(_evald))                                                                                 \
      {                                                                                            \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);                            \
	res = 1;                                                                                   \
      }                                                                                            \
    else                                                                                           \
      {                                                                                            \
	if (adj_test_do_debug)                                                                     \
	  fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);                          \
      }                                                                                            \
    res;                                                                                           \
  })

#define ADJ_TEST(_cond, _comment, _args...)                                                        \
  {                                                                                                \
    if (ADJ_TEST_I (_cond, _comment, ##_args))                                                     \
      {                                                                                            \
	return 1;                                                                                  \
	ASSERT (!("FAIL: " _comment));                                                             \
      }                                                                                            \
  }

typedef struct adj_test_main_t_
{
  u32 hw_if_index;
  vnet_hw_interface_t *hw;
  u8 initialized;
} adj_test_main_t;

static adj_test_main_t adj_test_main;
static u8 *adj_test_hw_address;

/*
 * Test-only ethernet interface plumbing. The ADJ API requires a real sw_if_index
 * so it can initialise rewrite metadata and neighbour adjacency state.
 */
static u8 *
format_adj_test_interface_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "adj-test-eth%d", dev_instance);
}

static uword
adj_test_interface_tx (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  clib_warning ("unexpected adj-test interface tx, leaking buffers...");
  return frame->n_vectors;
}

static clib_error_t *
adj_test_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (adj_test_interface_device_class, static) = {
  .name = "ADJ test interface",
  .format_device_name = format_adj_test_interface_name,
  .tx_function = adj_test_interface_tx,
  .admin_up_down_function = adj_test_interface_admin_up_down,
};

/*
 * Creates the single interface shared by all ADJ unit tests.
 *
 * The interface is intentionally kept for the lifetime of the test process and
 * each test only creates and releases neighbour adjacencies on top of it.
 */
static int
adj_test_mk_intf (void)
{
  adj_test_main_t *atm = &adj_test_main;
  clib_error_t *error;
  vnet_main_t *vnm;
  u32 res;
  u8 byte;
  int i;

  res = 0;
  vnm = vnet_get_main ();

  if (atm->initialized)
    {
      atm->hw = vnet_get_hw_interface (vnm, atm->hw_if_index);
      return res;
    }

  for (i = 0; i < 6; i++)
    {
      byte = 0xe0 + i;
      vec_add1 (adj_test_hw_address, byte);
    }

  vnet_eth_interface_registration_t eir = {};
  eir.dev_class_index = adj_test_interface_device_class.index;
  eir.dev_instance = 0;
  eir.address = adj_test_hw_address;

  atm->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  error = vnet_hw_interface_set_flags (vnm, atm->hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  ADJ_TEST ((NULL == error), "set test interface link-up");

  atm->hw = vnet_get_hw_interface (vnm, atm->hw_if_index);
  error = vnet_sw_interface_set_flags (vnm, atm->hw->sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  ADJ_TEST ((NULL == error), "set test interface admin-up");

  atm->hw = vnet_get_hw_interface (vnm, atm->hw_if_index);
  atm->initialized = 1;

  return res;
}

/*
 * Callbacks
 *
 */

/*
 * These unit tests exercise the same public BFD notifier payload contract used
 * by production code, without constructing private BFD session objects.
 */
void adj_bfd_notify (bfd_vnet_notifier_listener_t *listener, bfd_vnet_notifier_args_t *args);

/*
 * Delivers a synthetic BFD notifier event directly to the ADJ listener.
 */
static void
adj_test_call_adj_bfd_notify (bfd_listen_event_e event, const vnet_bfd_event_t *payload)
{
  bfd_vnet_notifier_args_t args = {
    .event = event,
    .payload = payload,
  };

  adj_bfd_notify (NULL, &args);
}

/*
 * Builds the default single-hop UDP BFD event used by the ADJ tests.
 */
static vnet_bfd_event_t
adj_test_bfd_event (adj_index_t ai)
{
  vnet_bfd_event_t event = {
    .session_index = 1,
    .adj_index = ai,
    .hop_type = BFD_HOP_TYPE_SINGLE,
    .transport = BFD_TRANSPORT_UDP4,
    .state = BFD_STATE_init,
  };

  return event;
}

/*
 * Creates and lock an IPv4 neighbour adjacency on the test interface.
 */
static adj_index_t
adj_test_create_adj (const ip46_address_t *nh)
{
  adj_test_main_t *atm = &adj_test_main;

  return adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4, nh, atm->hw->sw_if_index);
}

/*
 * Positive ADJ/BFD state-machine coverage:
 *
 * A single-hop BFD session attaches a BFD delegate to the adjacency. Without
 * that delegate the adjacency is considered usable; once the delegate exists,
 * the adjacency follows the BFD state distilled by adj_bfd_notify().
 */
static int
adj_test_bfd_positive (void)
{
  ip46_address_t nh = {
    .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a01),
  };
  adj_index_t ai;
  vnet_bfd_event_t event;
  int res;

  res = 0;
  ai = adj_test_create_adj (&nh);
  event = adj_test_bfd_event (ai);

  /*
   * No BFD delegate means no BFD restriction on adjacency usability.
   */
  ADJ_TEST (adj_is_up (ai), "adj is up without BFD delegate");

  /*
   * CREATE installs a BFD delegate in the conservative DOWN state.
   */
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (!adj_is_up (ai), "adj is down after BFD create");

  /*
   * Only BFD_STATE_up permits the adjacency to be used.
   */
  event.state = BFD_STATE_up;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (adj_is_up (ai), "adj is up after BFD update up");

  /*
   * All non-UP BFD states are treated as a forwarding stop signal.
   */
  event.state = BFD_STATE_init;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (!adj_is_up (ai), "adj is down after BFD update init");

  event.state = BFD_STATE_admin_down;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (!adj_is_up (ai), "adj is down after BFD update admin-down");

  event.state = BFD_STATE_up;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (adj_is_up (ai), "adj is up after second BFD update up");

  event.state = BFD_STATE_down;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (!adj_is_up (ai), "adj is down after BFD update down");

  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_DELETE, &event);
  ADJ_TEST (adj_is_up (ai), "adj is up after BFD delete");

  adj_unlock (ai);
  ADJ_TEST (0 == adj_nbr_db_size (), "ADJ DB size is %d", adj_nbr_db_size ());

  return res;
}

/*
 * Duplicate CREATE coverage:
 *
 * Make sure second CREATE for an adjacency that already has BFD tracking
 * does not allocate a second delegate or reset the existing delegate state.
 */
static int
adj_test_bfd_duplicate_create (void)
{
  ip46_address_t nh = {
    .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a02),
  };
  adj_index_t ai;
  vnet_bfd_event_t event;
  int res;

  res = 0;
  ai = adj_test_create_adj (&nh);
  event = adj_test_bfd_event (ai);

  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (!adj_is_up (ai), "adj is down after first BFD create");

  event.state = BFD_STATE_up;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (adj_is_up (ai), "adj is up after BFD update up");

  /*
   * CREATE only creates missing state. It does not reinterpret payload->state
   * or overwrite the UP state already stored in the delegate.
   */
  event.state = BFD_STATE_down;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (adj_is_up (ai), "duplicate BFD create leaves existing state");

  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_DELETE, &event);
  ADJ_TEST (adj_is_up (ai), "adj is up after duplicate-create test delete");

  adj_unlock (ai);
  ADJ_TEST (0 == adj_nbr_db_size (), "ADJ DB size is %d", adj_nbr_db_size ());

  return res;
}

/*
 * Negative ADJ/BFD coverage for events that adj_bfd_notify() should ignore
 * (according to original implementation)
 *
 * These cases document the listener's boundary: ADJ only consumes single-hop UDP
 * events that identify a valid adjacency and (those) already have delegate state
 * when processing UPDATE or DELETE events.
 */
static int
adj_test_bfd_negative (void)
{
  ip46_address_t nh = {
    .ip4.as_u32 = clib_host_to_net_u32 (0x0a0a0a03),
  };
  adj_index_t ai;
  vnet_bfd_event_t event;
  int res;

  res = 0;
  ai = adj_test_create_adj (&nh);

  /*
   * Multi-hop sessions attach to FIB entries, not adjacencies.
   */
  event = adj_test_bfd_event (ai);
  event.hop_type = BFD_HOP_TYPE_MULTI;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (adj_is_up (ai), "multi-hop BFD event is ignored by ADJ");

  /*
   * ADJ only knows how to find the adjacency for UDP4/UDP6 BFD transports.
   */
  event = adj_test_bfd_event (ai);
  event.transport = (bfd_transport_e) ~0;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (adj_is_up (ai), "unknown BFD transport is ignored by ADJ");

  /*
   * Events without an associated adjacency cannot install ADJ BFD state.
   */
  event = adj_test_bfd_event (INDEX_INVALID);
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_CREATE, &event);
  ADJ_TEST (adj_is_up (ai), "invalid BFD adj index is ignored by ADJ");

  /*
   * UPDATE and DELETE are no-ops until CREATE has installed a delegate.
   */
  event = adj_test_bfd_event (ai);
  event.state = BFD_STATE_down;
  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &event);
  ADJ_TEST (adj_is_up (ai), "BFD update without create is ignored by ADJ");

  adj_test_call_adj_bfd_notify (BFD_LISTEN_EVENT_DELETE, &event);
  ADJ_TEST (adj_is_up (ai), "BFD delete without create is ignored by ADJ");

  adj_unlock (ai);
  ADJ_TEST (0 == adj_nbr_db_size (), "ADJ DB size is %d", adj_nbr_db_size ());

  return res;
}

/*
 * CLI entry point for the ADJ unit tests.
 *
 * Individual subcommands are provided so the Python test wrapper can report a
 * precise failing scenario while the bare command still runs the full suite.
 */
static clib_error_t *
adj_test (CLIB_UNUSED (vlib_main_t *vm), unformat_input_t *input,
	  CLIB_UNUSED (vlib_cli_command_t *cmd_arg))
{
  int res;
  int test;

  res = 0;
  test = 0;

  if (unformat (input, "debug"))
    {
      adj_test_do_debug = 1;
    }

  if (UNFORMAT_END_OF_INPUT == unformat_check_input (input))
    {
      test = ADJ_TEST_ALL_CASES;
    }
  else if (unformat (input, "positive"))
    {
      test = ADJ_TEST_POSITIVE_CASES;
    }
  else if (unformat (input, "duplicate-create"))
    {
      test = ADJ_TEST_DUPLICASTE_CASES;
    }
  else if (unformat (input, "negative"))
    {
      test = ADJ_TEST_NEGATIVE_CASES;
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  if (UNFORMAT_END_OF_INPUT != unformat_check_input (input))
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  res += adj_test_mk_intf ();

  if (ADJ_TEST_POSITIVE_CASES == test)
    {
      res += adj_test_bfd_positive ();
    }
  else if ( ADJ_TEST_DUPLICASTE_CASES == test)
    {
      res += adj_test_bfd_duplicate_create ();
    }
  else if (ADJ_TEST_NEGATIVE_CASES == test)
    {
      res += adj_test_bfd_negative ();
    }
  else
    {
      res += adj_test_bfd_positive ();
      res += adj_test_bfd_duplicate_create ();
      res += adj_test_bfd_negative ();
    }

  fflush (NULL);
  if (res)
    {
      return clib_error_return (0, "ADJ Unit Test Failed");
    }
  else
    {
      return (NULL);
    }
}

VLIB_CLI_COMMAND (test_adj_command, static) = {
  .path = "test adj",
  .short_help = "adj unit tests - DO NOT RUN ON A LIVE SYSTEM",
  .function = adj_test,
};

clib_error_t *
adj_test_init (CLIB_UNUSED (vlib_main_t *vm))
{
  return 0;
}

VLIB_INIT_FUNCTION (adj_test_init);

// clang-format on
