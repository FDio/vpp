/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief STRUCTURAL EXAMPLE - IPv6 DAD Client in C
 *
 * This example shows the structure and API calls needed to implement
 * a DAD client. Exact signatures may vary depending on VPP/VAPI version.
 *
 * Refer to vapi/ip6_dad.api.vapi.h for exact signatures in your
 * VPP version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <vapi/vapi.h>
#include <vapi/ip6_dad.api.vapi.h>
#include <arpa/inet.h>

/* ===================================================================
 * 1. DAD STATE DEFINITIONS
 * =================================================================== */

#define DAD_STATE_IDLE	    0 /* No DAD in progress */
#define DAD_STATE_TENTATIVE 1 /* Address under test */
#define DAD_STATE_PREFERRED 2 /* DAD succeeded, IP usable */
#define DAD_STATE_DUPLICATE 3 /* Duplicate detected, IP remains configured */

/* ===================================================================
 * 2. APPLICATION CONTEXT STRUCTURE
 * =================================================================== */

typedef struct
{
  vapi_ctx_t ctx; /* VAPI context */
  int running;	  /* Main loop flag */
} app_ctx_t;

static app_ctx_t g_app = { NULL, 1 };

/* ===================================================================
 * 3. SIGNAL HANDLER (Ctrl+C)
 * =================================================================== */

static void
signal_handler (int signum)
{
  (void) signum;
  printf ("\nInterrupted, stopping...\n");
  g_app.running = 0;
}

/* ===================================================================
 * 4. UTILITY: FORMAT IPv6 ADDRESS
 * =================================================================== */

static void
format_ipv6 (const vapi_type_ip6_address *addr, char *buf, size_t len)
{
  inet_ntop (AF_INET6, addr, buf, len);
}

/* ===================================================================
 * 5. DAD EVENT CALLBACK
 *
 * This function is automatically called by VAPI when a DAD event
 * is received.
 * =================================================================== */

static vapi_error_e
dad_event_handler (vapi_ctx_t ctx, void *callback_ctx, vapi_msg_ip6_dad_event *msg)
{
  char addr_str[INET6_ADDRSTRLEN];
  vapi_payload_ip6_dad_event *event;

  (void) ctx;
  (void) callback_ctx;

  if (!msg)
    return VAPI_OK;

  event = &msg->payload;
  format_ipv6 (&event->address, addr_str, sizeof (addr_str));

  printf ("\n=== DAD Event Received ===\n");
  printf ("  Interface : %u\n", event->sw_if_index);
  printf ("  Address   : %s\n", addr_str);

  switch (event->state)
    {
    case DAD_STATE_TENTATIVE:
      if (event->dad_count == 0)
	{
	  printf ("  State     : TENTATIVE (initial)\n");
	  printf ("  Retries   : 0/%u\n", event->dad_transmits);
	}
      else
	{
	  printf ("  State     : TENTATIVE (retry %u/%u)\n", event->dad_count,
		  event->dad_transmits);
	}
      /* HERE: Your code to handle TENTATIVE state
       * Example: display progress, log, etc. */
      break;

    case DAD_STATE_PREFERRED:
      printf ("  State     : PREFERRED (success)\n");
      printf ("  ✓ Address is now OPERATIONAL\n");

      /* HERE: Your code to handle DAD success
       * Examples:
       * - Start services using this IP
       * - Update configuration
       * - Notify other components
       */
      break;

    case DAD_STATE_DUPLICATE:
      printf ("  State     : DUPLICATE (failure)\n");
      printf ("  ⚠ IP remains configured but marked DUPLICATE\n");

      /* HERE: Your code to handle duplicate
       * IMPORTANT: IP IS NOT REMOVED automatically
       *
       * Possible actions:
       * 1. Log error / send alert
       * 2. Generate new IPv6 address
       * 3. Disable interface
       * 4. Remove IP manually (if desired)
       * 5. Failover to backup IP
       *
       * Example code to remove IP:
       *   vapi_msg_sw_interface_add_del_address *req;
       *   req = vapi_alloc_sw_interface_add_del_address(ctx);
       *   req->payload.sw_if_index = event->sw_if_index;
       *   memcpy(&req->payload.prefix.address.un.ip6,
       *          &event->address, 16);
       *   req->payload.prefix.len = 64;  // or your prefix length
       *   req->payload.is_add = 0;  // 0 = remove
       *   vapi_sw_interface_add_del_address(ctx, req, NULL, NULL);
       */
      break;

    default:
      printf ("  State     : UNKNOWN (%u)\n", event->state);
    }

  printf ("\n");
  return VAPI_OK;
}

/* ===================================================================
 * 6. REGISTRATION CONFIRMATION CALLBACK
 *
 * NOTE: Exact signature depends on your VAPI version
 * Possible versions:
 *   - (ctx, callback_ctx, reply_msg)
 *   - (ctx, callback_ctx, rv, is_last, reply_payload)
 *
 * Refer to vapi/ip6_dad.api.vapi.h for your version
 * =================================================================== */

static vapi_error_e
register_confirm_handler (vapi_ctx_t ctx, void *callback_ctx,
			  /* exact signature depends on VAPI version */
			  vapi_msg_want_ip6_dad_events_reply *reply)
{
  (void) ctx;
  (void) callback_ctx;

  if (reply->payload.retval == 0)
    {
      printf ("✓ Registered for DAD events\n\n");
    }
  else
    {
      fprintf (stderr, "✗ Registration error: %d\n", reply->payload.retval);
      g_app.running = 0;
    }

  return VAPI_OK;
}

/* ===================================================================
 * 7. MAIN FUNCTION
 * =================================================================== */

int
main (void)
{
  vapi_error_e rv;
  vapi_msg_want_ip6_dad_events *req;

  printf ("=== IPv6 DAD Client - Structural Example ===\n\n");

  /* Install signal handler */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);

  /* -----------------------------------------------------------
   * STEP 1: CONNECT TO VPP
   * ----------------------------------------------------------- */
  printf ("Connecting to VPP...\n");

  rv = vapi_ctx_alloc (&g_app.ctx);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "Error: context allocation: %d\n", rv);
      return 1;
    }

  rv = vapi_connect (g_app.ctx, "dad_client", NULL, 32, 32, VAPI_MODE_BLOCKING, true);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "Error: VPP connection: %d\n", rv);
      vapi_ctx_free (g_app.ctx);
      return 1;
    }

  printf ("✓ Connected to VPP\n\n");

  /* -----------------------------------------------------------
   * STEP 2: REGISTER FOR DAD EVENTS
   * ----------------------------------------------------------- */
  printf ("Registering for DAD events...\n");

  req = vapi_alloc_want_ip6_dad_events (g_app.ctx);
  if (!req)
    {
      fprintf (stderr, "Error: message allocation\n");
      goto cleanup;
    }

  req->payload.enable_disable = true;
  req->payload.pid = getpid ();

  /* NOTE: Signature may vary depending on VAPI version */
  rv = vapi_want_ip6_dad_events (g_app.ctx, req, register_confirm_handler, NULL);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "Error: send request: %d\n", rv);
      goto cleanup;
    }

  /* Wait for confirmation */
  rv = vapi_dispatch_one (g_app.ctx);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "Error: dispatch: %d\n", rv);
      goto cleanup;
    }

  /* -----------------------------------------------------------
   * STEP 3: MAIN LOOP - RECEIVE EVENTS
   * ----------------------------------------------------------- */
  printf ("Waiting for DAD events (Ctrl+C to stop)...\n\n");

  while (g_app.running)
    {
      /* Register callback for events */
      vapi_set_event_cb (g_app.ctx, vapi_msg_id_ip6_dad_event, (vapi_event_cb) dad_event_handler,
			 NULL);

      /* Wait for and process events
       * NOTE: vapi_wait() may or may not require timeout
       * depending on version. Refer to vapi/vapi.h */
      rv = vapi_wait (g_app.ctx);
      if (rv == VAPI_OK)
	{
	  rv = vapi_dispatch (g_app.ctx);
	  if (rv != VAPI_OK)
	    {
	      fprintf (stderr, "Error: dispatch: %d\n", rv);
	      break;
	    }
	}
      else if (rv == VAPI_EAGAIN)
	{
	  /* No event available, wait a bit */
	  usleep (100000); /* 100ms */
	}
      else
	{
	  fprintf (stderr, "Error: wait: %d\n", rv);
	  break;
	}
    }

  /* -----------------------------------------------------------
   * STEP 4: UNREGISTER
   * ----------------------------------------------------------- */
  printf ("\nUnregistering...\n");

  req = vapi_alloc_want_ip6_dad_events (g_app.ctx);
  if (req)
    {
      req->payload.enable_disable = false;
      req->payload.pid = getpid ();
      vapi_want_ip6_dad_events (g_app.ctx, req, NULL, NULL);
      vapi_dispatch_one (g_app.ctx);
    }

cleanup:
  /* -----------------------------------------------------------
   * STEP 5: DISCONNECT
   * ----------------------------------------------------------- */
  printf ("Disconnecting...\n");
  vapi_disconnect (g_app.ctx);
  vapi_ctx_free (g_app.ctx);

  printf ("✓ Done\n");
  return 0;
}

/* ===================================================================
 * IMPLEMENTATION NOTES
 * ===================================================================
 *
 * 1. VAPI SIGNATURES: Exact signatures (callbacks, vapi_wait, etc.)
 *    may vary depending on VPP version. Always refer to:
 *    - build-root/install-vpp-native/vpp/include/vapi/vapi.h
 *    - build-root/install-vpp-native/vpp/include/vapi/ip6_dad.api.vapi.h
 *
 * 2. DUPLICATE HANDLING: Key point of this DAD evolution:
 *    - IP IS NO LONGER REMOVED automatically
 *    - It's up to the APPLICATION to decide what to do
 *    - Multiple strategies possible (see comments in handler)
 *
 * 3. VAPI MODE:
 *    - VAPI_MODE_BLOCKING: Simple, blocking calls
 *    - VAPI_MODE_NONBLOCKING: More complex, for performance
 *
 * 4. MULTI-THREADING:
 *    - One VAPI context per thread
 *    - Do not share vapi_ctx_t between threads
 *
 * 5. COMPILATION:
 *    gcc -I<vpp_include> -L<vpp_lib> \
 *        -lvapiclient -lvppinfra -lpthread \
 *        dad_client.c -o dad_client
 *
 * =================================================================== */
