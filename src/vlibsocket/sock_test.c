/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SOCKCLNT_SERVER_PORT 32741	/* whatever */

typedef signed char i8;
typedef signed short i16;
typedef signed int i32;
typedef signed long long i64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long uword;

#define VL_API_PACKED(x) x __attribute__ ((packed))

typedef VL_API_PACKED (struct _vl_api_sockclnt_create
		       {
		       u16 _vl_msg_id; u8 name[64];
		       u32 context;
		       }) vl_api_sockclnt_create_t;

typedef VL_API_PACKED (struct _vl_api_sockclnt_create_reply
		       {
		       u16 _vl_msg_id;
		       i32 response; u64 handle; u32 index; u32 context;
		       }) vl_api_sockclnt_create_reply_t;

typedef VL_API_PACKED (struct _vl_api_sockclnt_delete
		       {
		       u16 _vl_msg_id; u32 index;
		       u64 handle;
		       }) vl_api_sockclnt_delete_t;

typedef VL_API_PACKED (struct _vl_api_sockclnt_delete_reply
		       {
		       u16 _vl_msg_id; i32 response; u64 handle;
		       }) vl_api_sockclnt_delete_reply_t;

void
error (char *msg)
{
  perror (msg);
  exit (0);
}

int
main (int argc, char *argv[])
{
  int sockfd, portno, n;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  char buffer[256];
  int i;
  u32 nbytes;
  vl_api_sockclnt_create_t *mp;
  vl_api_sockclnt_create_reply_t *rp;
  char *rdptr;
  int total_bytes;

  for (i = 0; i < 1; i++)
    {
      portno = SOCKCLNT_SERVER_PORT;
      sockfd = socket (AF_INET, SOCK_STREAM, 0);
      if (sockfd < 0)
	error ("ERROR opening socket");
      server = gethostbyname ("localhost");
      if (server == NULL)
	{
	  fprintf (stderr, "ERROR, no such host\n");
	  exit (0);
	}
      bzero ((char *) &serv_addr, sizeof (serv_addr));
      serv_addr.sin_family = AF_INET;
      bcopy ((char *) server->h_addr,
	     (char *) &serv_addr.sin_addr.s_addr, server->h_length);
      serv_addr.sin_port = htons (portno);
      if (connect (sockfd, (const void *) &serv_addr, sizeof (serv_addr)) < 0)
	error ("ERROR connecting");

      memset (buffer, 0, sizeof (buffer));

      mp = (vl_api_sockclnt_create_t *) buffer;
      mp->_vl_msg_id = ntohs (13);	/* VL_API_SOCKCLNT_CREATE */
      strncpy ((char *) mp->name, "socket-test", sizeof (mp->name) - 1);
      mp->name[sizeof (mp->name) - 1] = 0;
      mp->context = 0xfeedface;
      /* length of the message, including the length itself */
      nbytes = sizeof (*mp) + sizeof (nbytes);
      nbytes = ntohl (nbytes);
      n = write (sockfd, &nbytes, sizeof (nbytes));
      if (n < 0)
	error ("ERROR writing len to socket");
      n = write (sockfd, mp, sizeof (*mp));
      if (n < 0)
	error ("ERROR writing msg to socket");

      memset (buffer, 0, sizeof (buffer));

      total_bytes = 0;
      rdptr = buffer;
      do
	{
	  n = read (sockfd, rdptr, sizeof (buffer) - (rdptr - buffer));
	  if (n < 0)
	    error ("ERROR reading from socket");
	  printf ("read %d bytes\n", n);
	  total_bytes += n;
	  rdptr += n;
	}
      while (total_bytes < sizeof (vl_api_sockclnt_create_reply_t) + 4);

      rp = (vl_api_sockclnt_create_reply_t *) (buffer + 4);
      /* VL_API_SOCKCLNT_CREATE_REPLY */
      if (ntohs (rp->_vl_msg_id) != 14)
	{
	  printf ("WARNING: msg id %d\n", ntohs (rp->_vl_msg_id));
	}

      printf ("response %d, handle 0x%llx, index %d, context 0x%x\n",
	      ntohl (rp->response), rp->handle, rp->index, rp->context);
      close (sockfd);
    }
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
