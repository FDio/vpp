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

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vcl/vppcom.h>

int main(){
  int client_session;
  char buffer[1024];
  struct sockaddr_in server_address;
  vppcom_endpt_t endpt;
  int rv;

  rv = vppcom_app_create ("test_vcl_listener_client");
  if (rv) return rv;

  client_session = vppcom_session_create(VPPCOM_PROTO_TCP, 0);

  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(9995);
  server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

  endpt.is_ip4 = (server_address.sin_family == AF_INET);
  endpt.ip = (uint8_t *) & server_address.sin_addr;
  endpt.port = (uint16_t) server_address.sin_port;


  vppcom_session_connect(client_session, &endpt);

  /*---- Read the message from the server into the buffer ----*/
  vppcom_session_read (client_session, buffer, 1024);

  /*---- Print the received message ----*/
  printf("Data received: %s",buffer);

  printf("Press ENTER key to Continue\n");
  (void) getchar();

  return 0;
}
