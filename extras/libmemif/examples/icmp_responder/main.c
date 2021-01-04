/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include <libmemif.h>
#include <common.h>

#define APP_NAME "icmp_responder_example"

#define IF_NAME	    "libmemif0"
#define IF_ID	    0
#define SOCKET_PATH "/run/vpp/memif.sock"
const uint8_t HW_ADDR[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
const uint8_t IP_ADDR[4] = { 192, 168, 1, 1 };

memif_connection_t intf;
int epfd;

/* informs user about connected status. private_ctx is used by user to identify
 * connection */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif connected!");
  int err;

  memif_connection_t *c = (memif_connection_t *) private_ctx;

  c->is_connected = 1;
  alloc_memif_buffers (c);

  err = memif_refill_queue (conn, 0, -1, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }

  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to
 * identify connection */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif disconnected!");

  memif_connection_t *c = (memif_connection_t *) private_ctx;

  c->is_connected = 0;
  free_memif_buffers (c);

  /* stop event polling thread */
  int err = memif_cancel_poll_event (memif_get_socket_handle (conn));
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("We are doomed...");

  return 0;
}

void
print_help ()
{
  printf ("LIBMEMIF EXAMPLE APP: %s", APP_NAME);
#ifdef ICMP_DBG
  printf (" (debug)");
#endif
  printf ("\n");
  printf ("==============================\n");
  print_version ();
  printf ("==============================\n");
  printf (
    "In this example, memif endpoint connects to an external application.\n");
  printf (
    "The example application can resolve ARP and reply to ICMPv4 packets.\n");
  printf ("The program will exit once the interface is disconnected.\n");
  printf ("==============================\n");
  printf ("Usage: icmp_responder [OPTIONS]\n\n");
  printf ("Options:\n");
  printf ("\t-r\tInterface role <slave|master>. Default: slave\n");
  printf ("\t-s\tSocket path. Supports abstract socket using @ before the "
	  "path. Default: /run/vpp/memif.sock\n");
  printf ("\t-i\tInterface id. Default: 0\n");
  printf ("\t-a\tIPv4 address. Default: 192.168.1.1\n");
  printf ("\t-h\tMac address. Default: aa:aa:aa:aa:aa:aa\n");
  printf ("\t-?\tShow help and exit.\n");
  printf ("\t-v\tShow libmemif and memif version information and exit.\n");
}

int
main (int argc, char *argv[])
{
  memif_socket_args_t memif_socket_args = { 0 };
  memif_socket_handle_t memif_socket;
  memif_conn_args_t memif_conn_args = { 0 };
  int opt, err, ret = 0;
  uint8_t is_master = 0;
  char socket_path[108];
  int id = IF_ID;

  strncpy (socket_path, SOCKET_PATH, strlen (SOCKET_PATH));

  /* prepare the private data */
  memset (&intf, 0, sizeof (intf));
  intf.packet_handler = icmp_packet_handler;
  memcpy (intf.ip_addr, IP_ADDR, 4);
  memcpy (intf.hw_addr, HW_ADDR, 6);

  while ((opt = getopt (argc, argv, "r:s:i:a:h:?v")) != -1)
    {
      switch (opt)
	{
	case 'r':
	  if (strncmp (optarg, "master", sizeof (optarg)) == 0)
	    {
	      is_master = 1;
	    }
	  else if (strncmp (optarg, "slave", sizeof (optarg)) == 0)
	    {
	      is_master = 0;
	    }
	  else
	    {
	      INFO ("Invalid role value: '%s'", optarg);
	      return -1;
	    }
	  break;
	case 's':
	  sprintf (socket_path, "%s", optarg);
	  break;
	case 'i':
	  id = atoi (optarg);
	  break;
	case 'a':
	  if (parse_ip4 (optarg, intf.ip_addr) != 0)
	    {
	      INFO ("Invalid ipv4 address: %s", optarg);
	      return -1;
	    }
	  break;
	case 'h':
	  if (parse_mac (optarg, intf.hw_addr) != 0)
	    {
	      INFO ("Invalid mac address: %s", optarg);
	      return -1;
	    }
	  break;
	case '?':
	  print_help ();
	  return 0;
	case 'v':
	  print_version ();
	  return 0;
	}
    }

  /** Create memif socket
   *
   * Interfaces are internally stored in a database referenced by memif socket.
   */
  sprintf (memif_socket_args.path, "%s", socket_path);
  /* Set application name */
  strncpy (memif_socket_args.app_name, APP_NAME, strlen (APP_NAME));

  /* configure autoconnect timer */
  if (is_master == 0)
    {
      memif_socket_args.connection_request_timer.it_value.tv_sec = 2;
      memif_socket_args.connection_request_timer.it_value.tv_nsec = 0;
      memif_socket_args.connection_request_timer.it_interval.tv_sec = 2;
      memif_socket_args.connection_request_timer.it_interval.tv_nsec = 0;
    }

  err = memif_create_socket (&memif_socket, &memif_socket_args, NULL);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create_socket: %s", memif_strerror (err));
      goto error;
    }

  /** Create memif interfaces
   *
   * Both interaces are assigned the same socket and same id to create a
   * loopback.
   */

  memif_conn_args.socket = memif_socket;
  memif_conn_args.interface_id = id;
  strncpy (memif_conn_args.interface_name, IF_NAME,
	   sizeof (memif_conn_args.interface_name));
  memif_conn_args.is_master = is_master;

  err =
    memif_create (&intf.conn, &memif_conn_args, on_connect, on_disconnect,
		  is_master ? responder : responder_zero_copy, (void *) &intf);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create_socket: %s", memif_strerror (err));
      return err;
    }

  do
    {
      err = memif_poll_event (memif_socket, -1);
    }
  while (err == MEMIF_ERR_SUCCESS);

  return 0;

error:
  ret = -1;
done:
  free_memif_buffers (&intf);
  memif_delete (&intf.conn);
  memif_delete_socket (&memif_socket);
  return ret;
}
