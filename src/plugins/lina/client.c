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

#include <vppinfra/format.h>
#include <vppinfra/socket.h>
#include "shared.h"

typedef struct
{
  u8 *filename;
  int verbose;
} test_main_t;

test_main_t test_main;

clib_error_t *
test_palloc (test_main_t * tm)
{
  clib_socket_t _sock = { 0 }, *sock = &_sock;
  clib_error_t *err;
  lina_msg_t msg;
  int i, fds[LINA_SHM_MAX_REGIONS];
  void *shm[LINA_SHM_MAX_REGIONS];
  lina_shm_hdr_t *shm_hdr;

  fformat (stdout, "Connecting to %s ...\n", tm->filename);

  /* connect to unix domain socket */
  sock->config = (char *) tm->filename;
  sock->flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;

  if ((err = clib_socket_init (sock)))
    return err;

  if ((err = clib_socket_recvmsg (sock, &msg, sizeof (lina_msg_t), fds,
				  LINA_SHM_MAX_REGIONS)))
    return err;

  fformat (stdout, "Connected to instance %u ...\n", msg.instance);

  for (i = 0; i < msg.n_regions; i++)
    {
      if ((shm[i] = mmap (0, msg.region_size[i], PROT_READ | PROT_WRITE,
			  MAP_SHARED, fds[i], 0)) == MAP_FAILED)
	return clib_error_return_unix (0, "mmap");
      fformat (stdout, "region %u size %u fd %u mapped at %p...\n", i,
	       msg.region_size[i], fds[i], shm[i]);
    }

  shm_hdr = shm[0];
  if (shm_hdr->cookie != LINA_SHM_HDR_COOKIE)
    return clib_error_return (0, "bad cookie 0x%x", shm_hdr->cookie);

  fformat (stdout, "%u rings, ring size is %u...\n", shm_hdr->n_rings,
	   1 << shm_hdr->log2_ring_sz);

  u32 ring = 0;
  u32 last_head[shm_hdr->n_rings];
  u32 mask = (1 << shm_hdr->log2_ring_sz) - 1;

  memset (last_head, 0, sizeof (last_head));
  while (1)
    {
      lina_shm_ring_hdr_t *ring_hdr;

      ring_hdr = lina_get_shm_ring (shm_hdr, ring);
      while (ring_hdr->head != last_head[ring])
	{
          lina_shm_desc_t *d;
	  u8 *data;
          d = lina_get_shm_desc (shm_hdr, ring, last_head[ring]);
	  fformat (stdout, "ring %u desc %u region %u offset %u len %u\n",
		   ring, last_head[ring], d->region, d->offset, d->length);

	  data = shm[d->region] + d->offset;
	  fformat (stderr, "%U\n", format_hexdump, data, d->length > 128 ?
		   128 : d->length);
	  last_head[ring] = (last_head[ring] + 1) & mask;
	}

      ring++;
      if (ring >= shm_hdr->n_rings)
	ring = 0;
    }

  clib_socket_close (sock);

  return 0;
}

clib_error_t *
test_palloc_main (unformat_input_t * i)
{
  test_main_t *tm = &test_main;
  clib_error_t *error;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "file %s", &tm->filename))
	;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_palloc (tm);

  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int rv = 0;
  clib_error_t *error;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  error = test_palloc_main (&i);
  if (error)
    {
      clib_error_report (error);
      rv = 1;
    }
  unformat_free (&i);

  return rv;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
