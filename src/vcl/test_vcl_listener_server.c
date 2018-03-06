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


#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#include <vcl/vppcom.h>
#include <unistd.h>

char MESSAGE[] = "Hello, World!\n";

static const int PORT = 9995;

void
listener_cb (uint32_t new_session_index, vppcom_endpt_t *ep, void *stuff)
{

  vppcom_session_write (new_session_index, &MESSAGE, sizeof (MESSAGE));
  printf ("\n Heard from port: %d\n", ep->port);
}


typedef struct vppcomm_listener_main_
{
  int new_fd;

  struct event *event;

} vppcomm_listener_main_t;

vppcomm_listener_main_t _vlm_main;
vppcomm_listener_main_t *vlm = &_vlm_main;


int
main (int argc, char **argv)
{

  int rv;
  struct sockaddr_in sin;
  uint32_t listen_fd;
  vppcom_endpt_t endpt;

  //Address stuff
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (PORT);
  //sin.sin_addr.s_addr = inet_addr("127.0.0.1");

  endpt.is_ip4 = (sin.sin_family == AF_INET);
  endpt.ip = (uint8_t *) & sin.sin_addr;
  endpt.port = (uint16_t) sin.sin_port;

  //VCL stuff
  rv = vppcom_app_create ("test_vcl_listener_server");
  if (rv) return rv;

  listen_fd = vppcom_session_create (VPPCOM_PROTO_TCP,
					  0 /* is_nonblocking */ );

  rv = vppcom_session_bind (listen_fd, &endpt);

  //Make a listener and dispatch
  rv = vppcom_session_register_listener (listen_fd, listener_cb, 0,
					    0, 0, &MESSAGE);

  if (rv)
    {
      fprintf (stderr, "Could not create a listener!\n");
      return 1;
    }

  while (1)
    {
      sleep (3);
    }

  printf ("done\n");
  return 0;
}


