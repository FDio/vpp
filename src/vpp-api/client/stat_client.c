/*
 *------------------------------------------------------------------
 * stat_client.c - Library for access to VPP statistics segment
 *
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <regex.h>
#include <assert.h>
#include <vppinfra/vec.h>
#include <vppinfra/lock.h>
#include "stat_client.h"

typedef struct
{
  uint64_t current_epoch;
  volatile int segment_ready;
  stat_segment_shared_header_t *shared_header;
  clib_spinlock_t stat_segment_lockp;	/* Spinlock for the stats segment */
  stat_segment_directory_entry_t *counter_vector;
} stat_client_main_t;

stat_client_main_t stat_client_main;

static int
recv_fds (int sock)
{
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  int fd;
  char iobuf[1];
  struct iovec io = {
    .iov_base = iobuf,
    .iov_len = sizeof (iobuf)
  };
  union
  {				/* Ancillary data buffer, wrapped in a union
				   in order to ensure it is suitably aligned */
    char buf[CMSG_SPACE (sizeof (fd))];
    struct cmsghdr align;
  } u;

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof (u.buf);

  ssize_t size;
  if ((size = recvmsg (sock, &msg, 0)) < 0)
    {
      perror ("recvmsg failed");
      return -1;
    }
  cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    {
      int *fdp = (int *) CMSG_DATA (cmsg);
      fd = *fdp;
    }
  return fd;
}

static void *
get_pointer (void *start, uint64_t offset)
{
  return ((char *) start + offset);
}

static stat_segment_directory_entry_t *
get_stat_vector (void)
{
  stat_client_main_t *sm = &stat_client_main;
  assert (sm->shared_header);
  uint64_t offset =
    (uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET];
  return get_pointer (sm->shared_header, offset);
}

static bool
epoch_changed (void)
{
  stat_client_main_t *sm = &stat_client_main;
  /* Cached pointers OK? */
  return (sm->current_epoch !=
	  (uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH]);
}

int
stat_segment_connect (char *socket_name)
{
  stat_client_main_t *sm = &stat_client_main;
  int fd = -1;
  int sock;

  memset (sm, 0, sizeof (*sm));

  if ((sock = socket (AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    {
      perror ("Couldn't open socket");
      return -1;
    }

  struct sockaddr_un un = { 0 };
  un.sun_family = AF_UNIX;
  strncpy ((char *) un.sun_path, socket_name, sizeof (un.sun_path) - 1);
  if (connect (sock, (struct sockaddr *) &un, sizeof (struct sockaddr_un)) <
      0)
    {
      perror ("connect");
      return -1;
    }

  if ((fd = recv_fds (sock)) < 0)
    {
      fprintf (stderr, "Receiving file descriptor failed\n");
      return -1;
    }
  close (sock);

  /* mmap shared memory segment, look at the header to figure out actual size and remap. */
  void *addr;
  struct stat st = { 0 };
  if (fstat (fd, &st) == -1)
    {
      perror ("mmap");
      return -1;
    }
  if ((addr =
       mmap (NULL, st.st_blksize, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	     0)) == MAP_FAILED)
    {
      perror ("mmap");
      return -1;
    }

  size_t m_size = ((stat_segment_shared_header_t *) addr)->ssvm_size;
  munmap (addr, st.st_blksize);
  if ((addr =
       mmap (NULL, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	     0)) == MAP_FAILED)
    {
      perror ("mmap");
      return -1;
    }

  sm->shared_header = addr;

  /* Pick up the segment lock from the shared memory header */
  uint64_t offset =
    (uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_LOCK];
  sm->stat_segment_lockp = (clib_spinlock_t) get_pointer (addr, offset);

  offset = (uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET];
  sm->counter_vector = get_pointer (addr, offset);

  sm->segment_ready = 1;

  return 0;
}

void
stat_segment_disconnect (void)
{
  stat_client_main_t *sm = &stat_client_main;
  munmap (sm->shared_header, sm->shared_header->ssvm_size);

  return;
}

double
stat_segment_heartbeat (void)
{
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *vec = get_stat_vector ();
  double *hb = get_pointer (sm->shared_header, vec[4].offset);
  return *hb;
}

stat_segment_data_t
copy_data (stat_segment_directory_entry_t * ep)
{
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_data_t result = { 0 };
  int i;
  vlib_counter_t **combined_c;	/* Combined counter */
  counter_t **simple_c;		/* Simple counter */
  counter_t *error_base;
  double *double_v;
  uint64_t offset, *offset_vector;

  assert (sm->shared_header);

  result.type = ep->type;
  result.name = strdup (ep->name);
  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_POINTER:
      double_v = get_pointer (sm->shared_header, ep->offset);
      result.scalar_value = *double_v;
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      simple_c = get_pointer (sm->shared_header, ep->offset);
      result.simple_counter_vec = vec_dup (simple_c);
      offset_vector = get_pointer (sm->shared_header, ep->offset_vector);
      for (i = 0; i < vec_len (simple_c); i++)
	{
	  counter_t *cb = get_pointer (sm->shared_header, offset_vector[i]);
	  result.simple_counter_vec[i] = vec_dup (cb);
	}
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      combined_c = get_pointer (sm->shared_header, ep->offset);
      result.combined_counter_vec = vec_dup (combined_c);
      offset_vector = get_pointer (sm->shared_header, ep->offset_vector);
      for (i = 0; i < vec_len (combined_c); i++)
	{
	  vlib_counter_t *cb =
	    get_pointer (sm->shared_header, offset_vector[i]);
	  result.combined_counter_vec[i] = vec_dup (cb);
	}
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      offset =
	(uint64_t) sm->
	shared_header->opaque[STAT_SEGMENT_OPAQUE_ERROR_OFFSET];
      error_base = get_pointer (sm->shared_header, offset);
      result.error_value = error_base[ep->offset];
      break;

    default:
      fprintf (stderr, "Unknown type: %d", ep->type);
    }
  return result;
}

void
stat_segment_data_free (stat_segment_data_t * res)
{
  int i, j;
  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  for (j = 0; j < vec_len (res[i].simple_counter_vec); j++)
	    vec_free (res[i].simple_counter_vec[j]);
	  vec_free (res[i].simple_counter_vec);
	  break;
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  for (j = 0; j < vec_len (res[i].combined_counter_vec); j++)
	    vec_free (res[i].combined_counter_vec[j]);
	  vec_free (res[i].combined_counter_vec);
	  break;
	default:
	  ;
	}
      free (res[i].name);
    }
  vec_free (res);
}

uint32_t *
stat_segment_ls (uint8_t ** patterns)
{
  stat_client_main_t *sm = &stat_client_main;
  uint32_t *dir = 0;
  regex_t regex[vec_len (patterns)];

  int i, j;
  for (i = 0; i < vec_len (patterns); i++)
    {
      int rv = regcomp (&regex[i], (char *) patterns[i], 0);
      if (rv)
	{
	  fprintf (stderr, "Could not compile regex %s\n", patterns[i]);
	  return dir;
	}
    }

  clib_spinlock_lock (&sm->stat_segment_lockp);

  stat_segment_directory_entry_t *counter_vec = get_stat_vector ();
  for (j = 0; j < vec_len (counter_vec); j++)
    {
      for (i = 0; i < vec_len (patterns); i++)
	{
	  int rv = regexec (&regex[i], counter_vec[j].name, 0, NULL, 0);
	  if (rv == 0)
	    {
	      vec_add1 (dir, j);
	      break;
	    }
	}
      if (vec_len (patterns) == 0)
	vec_add1 (dir, j);
    }

  clib_spinlock_unlock (&sm->stat_segment_lockp);

  if (epoch_changed ())
    {
      sm->current_epoch =
	(uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH];
      uint64_t offset =
	(uint64_t) sm->shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET];
      sm->counter_vector = get_pointer (sm->shared_header, offset);
    }

  for (i = 0; i < vec_len (patterns); i++)
    regfree (&regex[i]);

  return dir;
}

stat_segment_data_t *
stat_segment_dump (uint32_t * stats)
{
  int i;
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;

  if (epoch_changed ())
    {
      return 0;
    }

  clib_spinlock_lock (&sm->stat_segment_lockp);

  for (i = 0; i < vec_len (stats); i++)
    {
      /* Collect counter */
      ep = vec_elt_at_index (sm->counter_vector, stats[i]);
      vec_add1 (res, copy_data (ep));
    }
  clib_spinlock_unlock (&sm->stat_segment_lockp);

  return res;
}

/* Wrapper for accessing vectors from other languages */
int
stat_segment_vec_len (void *vec)
{
  return vec_len (vec);
}

/* Create a vector from a string (or add to existing) */
u8 **
stat_segment_string_vector (u8 ** string_vector, char *string)
{
  u8 *name = 0;
  name = vec_dup ((u8 *) string);
  vec_add1 (string_vector, (u8 *) name);
  return string_vector;
}

stat_segment_data_t *
stat_segment_dump_entry (uint32_t index)
{
  stat_client_main_t *sm = &stat_client_main;
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;

  clib_spinlock_lock (&sm->stat_segment_lockp);

  /* Collect counter */
  ep = vec_elt_at_index (sm->counter_vector, index);
  vec_add1 (res, copy_data (ep));

  clib_spinlock_unlock (&sm->stat_segment_lockp);

  return res;
}

char *
stat_segment_index_to_name (uint32_t index)
{
  char *name;
  stat_segment_directory_entry_t *counter_vec = get_stat_vector ();
  stat_segment_directory_entry_t *ep;
  ep = vec_elt_at_index (counter_vec, index);
  name = strdup (ep->name);
  return name;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
