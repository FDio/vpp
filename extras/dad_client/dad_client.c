/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/**
 * @file dad_client.c
 * @brief IPv6 DAD Client Example using VAPI
 *
 * This is a structural example demonstrating how to integrate with
 * VPP's IPv6 DAD event notification system using VAPI.
 *
 * Note: This example shows the integration pattern. Actual implementation
 * may require adjustments based on your VPP version and build environment.
 *
 * Key concepts demonstrated:
 * - VAPI connection setup
 * - DAD configuration via API
 * - Event registration
 * - Event callback handling
 * - Proper cleanup
 *
 * Expected event sequence for a successful DAD:
 * 1. TENTATIVE (dad_count=0) - Initial state
 * 2. TENTATIVE (dad_count=1..N) - After each NS probe
 * 3. PREFERRED - Address validated, ready to use
 *
 * Or in case of conflict:
 * 1. TENTATIVE (dad_count=0) - Initial state
 * 2. DUPLICATE - Conflict detected, IP remains configured!
 *
 * Important: When DUPLICATE is detected, the IP address remains configured.
 * The application must decide how to handle this.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Note: In a real implementation, these would be:
 * #include <vapi/vapi.h>
 * #include <vapi/ip6_dad.api.vapi.h>
 */

/* DAD state constants (from VPP API) */
#define DAD_STATE_IDLE	    0
#define DAD_STATE_TENTATIVE 1
#define DAD_STATE_PREFERRED 2
#define DAD_STATE_DUPLICATE 3

/* Global flag for clean shutdown */
static volatile int keep_running = 1;

/**
 * Signal handler for clean shutdown
 */
static void
signal_handler (int signum)
{
  (void) signum;
  keep_running = 0;
}

/**
 * Convert DAD state to string
 */
static const char *
dad_state_to_string (int state)
{
  switch (state)
    {
    case DAD_STATE_IDLE:
      return "IDLE";
    case DAD_STATE_TENTATIVE:
      return "TENTATIVE";
    case DAD_STATE_PREFERRED:
      return "PREFERRED";
    case DAD_STATE_DUPLICATE:
      return "DUPLICATE";
    default:
      return "UNKNOWN";
    }
}

/**
 * Handle DAD event notification
 *
 * This callback is invoked by VAPI when a DAD event is received.
 *
 * @param event Pointer to the DAD event structure
 */
static void
handle_dad_event (/* vapi_msg_ip6_dad_event *event */ void *event_data)
{
  /* In a real implementation, event_data would be cast to:
   * vapi_msg_ip6_dad_event *event = (vapi_msg_ip6_dad_event *)event_data;
   *
   * For this structural example, we'll simulate the event structure:
   */
  struct
  {
    int sw_if_index;
    char address[40]; /* IPv6 address as string */
    int state;
    int dad_count;
  } *event = event_data;

  /* Display event details */
  printf ("\n[DAD Event]\n");
  printf ("  Interface:  sw_if_index=%d\n", event->sw_if_index);
  printf ("  Address:    %s\n", event->address);
  printf ("  State:      %s (%d)\n", dad_state_to_string (event->state), event->state);
  printf ("  DAD Count:  %d\n", event->dad_count);

  /* Interpret the event */
  switch (event->state)
    {
    case DAD_STATE_TENTATIVE:
      if (event->dad_count == 0)
	{
	  printf ("  → DAD process started (initial TENTATIVE)\n");
	}
      else
	{
	  printf ("  → NS probe #%d sent, no conflict detected yet\n", event->dad_count);
	}
      break;

    case DAD_STATE_PREFERRED:
      printf ("  → ✓ DAD succeeded! Address is PREFERRED and ready to "
	      "use\n");
      break;

    case DAD_STATE_DUPLICATE:
      printf ("  → ✗ DUPLICATE DETECTED!\n");
      printf ("  → ⚠️  Address remains configured but should not be used\n");
      printf ("  → Application must decide: remove address or take other action\n");

      /* Application logic for handling duplicates goes here.
       * Options include:
       * 1. Remove the address via API
       * 2. Generate a new address (e.g., privacy extensions)
       * 3. Alert the user/administrator
       * 4. Log the event for security monitoring
       */
      break;

    default:
      printf ("  → Unknown state\n");
      break;
    }
}

/**
 * Main program
 */
int
main (int argc, char *argv[])
{
  (void) argc;
  (void) argv;

  /* In a real implementation, you would:
   * 1. Initialize VAPI
   * 2. Connect to VPP
   * 3. Enable DAD via API
   * 4. Register for events
   * 5. Enter event loop
   * 6. Cleanup on exit
   */

  printf ("============================================================\n");
  printf ("VPP IPv6 DAD Event Monitor (Structural Example)\n");
  printf ("============================================================\n");
  printf ("\n");
  printf ("This is a structural example showing VAPI integration "
	  "patterns.\n");
  printf ("For a working example, see the Python implementation: "
	  "dad_client.py\n");
  printf ("\n");

  /* Setup signal handlers */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);

  printf ("Step-by-step integration guide:\n");
  printf ("\n");

  printf ("1. Initialize VAPI connection\n");
  printf ("   Example:\n");
  printf ("     vapi_ctx_t ctx;\n");
  printf ("     vapi_error_e rv = vapi_ctx_alloc(&ctx);\n");
  printf ("     if (rv != VAPI_OK) { /* handle error */ }\n");
  printf ("\n");

  printf ("2. Connect to VPP\n");
  printf ("   Example:\n");
  printf ("     rv = vapi_connect(ctx, \"dad_client\", NULL,\n");
  printf ("                       DEFAULT_MAX_OUTSTANDING_REQUESTS,\n");
  printf ("                       DEFAULT_RESPONSE_QUEUE_SIZE);\n");
  printf ("     if (rv != VAPI_OK) { /* handle error */ }\n");
  printf ("\n");

  printf ("3. Enable and configure DAD\n");
  printf ("   Example:\n");
  printf ("     vapi_msg_ip6_dad_enable_disable *msg =\n");
  printf ("       vapi_alloc_ip6_dad_enable_disable(ctx);\n");
  printf ("     msg->payload.enable = 1;\n");
  printf ("     msg->payload.dad_transmits = 1;        /* RFC 4862 "
	  "default */\n");
  printf ("     msg->payload.dad_retransmit_delay = 1.0; /* 1 second */\n");
  printf ("     vapi_ip6_dad_enable_disable(ctx, msg, callback, NULL);\n");
  printf ("\n");

  printf ("4. Register for event notifications\n");
  printf ("   Example:\n");
  printf ("     vapi_msg_want_ip6_dad_events *evt_msg =\n");
  printf ("       vapi_alloc_want_ip6_dad_events(ctx);\n");
  printf ("     evt_msg->payload.enable = 1;\n");
  printf ("     evt_msg->payload.pid = getpid();\n");
  printf ("     vapi_want_ip6_dad_events(ctx, evt_msg, callback, NULL);\n");
  printf ("\n");

  printf ("5. Setup event handler\n");
  printf ("   Example:\n");
  printf ("     vapi_set_event_cb(ctx, vapi_msg_id_ip6_dad_event,\n");
  printf ("                       handle_dad_event, NULL);\n");
  printf ("\n");

  printf ("6. Enter event loop\n");
  printf ("   Example:\n");
  printf ("     while (keep_running) {\n");
  printf ("       rv = vapi_dispatch(ctx);\n");
  printf ("       if (rv != VAPI_OK) { /* handle error */ }\n");
  printf ("     }\n");
  printf ("\n");

  printf ("7. Cleanup\n");
  printf ("   Example:\n");
  printf ("     /* Unregister from events */\n");
  printf ("     evt_msg->payload.enable = 0;\n");
  printf ("     vapi_want_ip6_dad_events(ctx, evt_msg, NULL, NULL);\n");
  printf ("     vapi_disconnect(ctx);\n");
  printf ("     vapi_ctx_free(ctx);\n");
  printf ("\n");

  printf ("============================================================\n");
  printf ("Event Handling Example\n");
  printf ("============================================================\n");
  printf ("\n");
  printf ("Simulating DAD events for address 2001:db8::1:\n");
  printf ("\n");

  /* Simulate event sequence */
  struct
  {
    int sw_if_index;
    char address[40];
    int state;
    int dad_count;
  } simulated_events[] = {
    { 1, "2001:db8::1", DAD_STATE_TENTATIVE, 0 },
    { 1, "2001:db8::1", DAD_STATE_TENTATIVE, 1 },
    { 1, "2001:db8::1", DAD_STATE_PREFERRED, 1 },
  };

  for (int i = 0; i < 3; i++)
    {
      handle_dad_event (&simulated_events[i]);
      sleep (1);
    }

  printf ("\n");
  printf ("============================================================\n");
  printf ("Duplicate Detection Example\n");
  printf ("============================================================\n");
  printf ("\n");
  printf ("Simulating duplicate detection for address 2001:db8::2:\n");
  printf ("\n");

  struct
  {
    int sw_if_index;
    char address[40];
    int state;
    int dad_count;
  } conflict_events[] = {
    { 1, "2001:db8::2", DAD_STATE_TENTATIVE, 0 },
    { 1, "2001:db8::2", DAD_STATE_DUPLICATE, 0 },
  };

  for (int i = 0; i < 2; i++)
    {
      handle_dad_event (&conflict_events[i]);
      sleep (1);
    }

  printf ("\n");
  printf ("============================================================\n");
  printf ("Summary\n");
  printf ("============================================================\n");
  printf ("\n");
  printf ("This structural example demonstrates:\n");
  printf ("  ✓ Event callback structure\n");
  printf ("  ✓ State interpretation\n");
  printf ("  ✓ Duplicate handling considerations\n");
  printf ("\n");
  printf ("Key Points:\n");
  printf ("  • IP addresses remain configured in DUPLICATE state\n");
  printf ("  • Applications must implement their own duplicate handling "
	  "policy\n");
  printf ("  • Events provide complete state transition visibility\n");
  printf ("\n");
  printf ("For a complete, working implementation, see: dad_client.py\n");
  printf ("\n");

  return 0;
}
