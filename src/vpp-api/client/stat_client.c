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
#include <stdatomic.h>
#include <vpp/stats/stat_segment.h>

struct stat_client_main_t
{
  uint64_t current_epoch;
  stat_segment_shared_header_t *shared_header;
  stat_segment_directory_entry_t *directory_vector;
  ssize_t memory_size;
};

stat_client_main_t stat_client_main;

stat_client_main_t *
stat_client_get (void)
{
  stat_client_main_t *sm;
  sm = (stat_client_main_t *) malloc (sizeof (stat_client_main_t));
  clib_memset (sm, 0, sizeof (stat_client_main_t));
  return sm;
}

void
stat_client_free (stat_client_main_t * sm)
{
  free (sm);
}

static int
recv_fd (int sock)
{
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  int fd = -1;
  char iobuf[1];
  struct iovec io = {.iov_base = iobuf,.iov_len = sizeof (iobuf) };
  union
  {
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
  if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    {
      memmove (&fd, CMSG_DATA (cmsg), sizeof (fd));
    }
  return fd;
}

static stat_segment_directory_entry_t *
get_stat_vector_r (stat_client_main_t * sm)
{
  ASSERT (sm->shared_header);
  return stat_segment_pointer (sm->shared_header,
			       sm->shared_header->directory_offset);
}

static stat_segment_directory_entry_t *
get_stat_vector (void)
{
  stat_client_main_t *sm = &stat_client_main;
  return get_stat_vector_r (sm);
}

int
stat_segment_connect_r (const char *socket_name, stat_client_main_t * sm)
{
  int mfd = -1;
  int sock;

  clib_memset (sm, 0, sizeof (*sm));
  if ((sock = socket (AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    {
      perror ("Stat client couldn't open socket");
      return -1;
    }

  struct sockaddr_un un = { 0 };
  un.sun_family = AF_UNIX;
  strncpy ((char *) un.sun_path, socket_name, sizeof (un.sun_path) - 1);
  if (connect (sock, (struct sockaddr *) &un, sizeof (struct sockaddr_un)) <
      0)
    {
      close (sock);
      return -2;
    }

  if ((mfd = recv_fd (sock)) < 0)
    {
      close (sock);
      fprintf (stderr, "Receiving file descriptor failed\n");
      return -3;
    }
  close (sock);

  /* mmap shared memory segment. */
  void *memaddr;
  struct stat st = { 0 };

  if (fstat (mfd, &st) == -1)
    {
      perror ("mmap fstat failed");
      return -4;
    }
  if ((memaddr =
       mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, mfd, 0)) == MAP_FAILED)
    {
      perror ("mmap map failed");
      return -5;
    }

  sm->memory_size = st.st_size;
  sm->shared_header = memaddr;
  sm->directory_vector =
    stat_segment_pointer (memaddr, sm->shared_header->directory_offset);

  return 0;
}

int
stat_segment_connect (const char *socket_name)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_connect_r (socket_name, sm);
}

void
stat_segment_disconnect_r (stat_client_main_t * sm)
{
  munmap (sm->shared_header, sm->memory_size);
  return;
}

void
stat_segment_disconnect (void)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_disconnect_r (sm);
}

double
stat_segment_heartbeat_r (stat_client_main_t * sm)
{
  stat_segment_directory_entry_t *vec = get_stat_vector_r (sm);
  double *hb = stat_segment_pointer (sm->shared_header, vec[4].offset);
  return *hb;
}

double
stat_segment_heartbeat (void)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_heartbeat_r (sm);
}

stat_segment_data_t
copy_data (stat_segment_directory_entry_t * ep, stat_client_main_t * sm)
{
  stat_segment_data_t result = { 0 };
  int i;
  vlib_counter_t **combined_c;	/* Combined counter */
  counter_t **simple_c;		/* Simple counter */
  counter_t *error_base;
  uint64_t *offset_vector;

  assert (sm->shared_header);

  result.type = ep->type;
  result.name = strdup (ep->name);
  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      result.scalar_value = ep->value;
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      if (ep->offset == 0)
	return result;
      simple_c = stat_segment_pointer (sm->shared_header, ep->offset);
      result.simple_counter_vec = vec_dup (simple_c);
      offset_vector =
	stat_segment_pointer (sm->shared_header, ep->offset_vector);
      for (i = 0; i < vec_len (simple_c); i++)
	{
	  counter_t *cb =
	    stat_segment_pointer (sm->shared_header, offset_vector[i]);
	  result.simple_counter_vec[i] = vec_dup (cb);
	}
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      if (ep->offset == 0)
	return result;
      combined_c = stat_segment_pointer (sm->shared_header, ep->offset);
      result.combined_counter_vec = vec_dup (combined_c);
      offset_vector =
	stat_segment_pointer (sm->shared_header, ep->offset_vector);
      for (i = 0; i < vec_len (combined_c); i++)
	{
	  vlib_counter_t *cb =
	    stat_segment_pointer (sm->shared_header, offset_vector[i]);
	  result.combined_counter_vec[i] = vec_dup (cb);
	}
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      error_base =
	stat_segment_pointer (sm->shared_header,
			      sm->shared_header->error_offset);
      result.error_value = error_base[ep->index];
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


typedef struct
{
  uint64_t epoch;
} stat_segment_access_t;

static void
stat_segment_access_start (stat_segment_access_t * sa,
			   stat_client_main_t * sm)
{
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  sa->epoch = shared_header->epoch;
  while (shared_header->in_progress != 0)
    ;
}

static bool
stat_segment_access_end (stat_segment_access_t * sa, stat_client_main_t * sm)
{
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  if (shared_header->epoch != sa->epoch || shared_header->in_progress)
    return false;
  return true;
}

uint32_t *
stat_segment_ls_r (uint8_t ** patterns, stat_client_main_t * sm)
{
  stat_segment_access_t sa;

  uint32_t *dir = 0;
  regex_t regex[vec_len (patterns)];

  int i, j;
  for (i = 0; i < vec_len (patterns); i++)
    {
      int rv = regcomp (&regex[i], (const char *) patterns[i], 0);
      if (rv)
	{
	  fprintf (stderr, "Could not compile regex %s\n", patterns[i]);
	  return dir;
	}
    }

  stat_segment_access_start (&sa, sm);

  stat_segment_directory_entry_t *counter_vec = get_stat_vector_r (sm);
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

  for (i = 0; i < vec_len (patterns); i++)
    regfree (&regex[i]);

  if (!stat_segment_access_end (&sa, sm))
    {
      /* Failed, clean up */
      vec_free (dir);
      return 0;

    }

  /* Update last version */
  sm->current_epoch = sa.epoch;
  return dir;
}

uint32_t *
stat_segment_ls (uint8_t ** patterns)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_ls_r ((uint8_t **) patterns, sm);
}

stat_segment_data_t *
stat_segment_dump_r (uint32_t * stats, stat_client_main_t * sm)
{
  int i;
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;
  stat_segment_access_t sa;

  /* Has directory been update? */
  if (sm->shared_header->epoch != sm->current_epoch)
    return 0;

  stat_segment_access_start (&sa, sm);
  for (i = 0; i < vec_len (stats); i++)
    {
      /* Collect counter */
      ep = vec_elt_at_index (sm->directory_vector, stats[i]);
      vec_add1 (res, copy_data (ep, sm));
    }

  if (stat_segment_access_end (&sa, sm))
    return res;

  fprintf (stderr, "Epoch changed while reading, invalid results\n");
  // TODO increase counter
  return 0;
}

stat_segment_data_t *
stat_segment_dump (uint32_t * stats)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_dump_r (stats, sm);
}

/* Wrapper for accessing vectors from other languages */
int
stat_segment_vec_len (void *vec)
{
  return vec_len (vec);
}

void
stat_segment_vec_free (void *vec)
{
  vec_free (vec);
}

/* Create a vector from a string (or add to existing) */
uint8_t **
stat_segment_string_vector (uint8_t ** string_vector, const char *string)
{
  uint8_t *name = 0;
  size_t len = strlen (string);

  vec_validate_init_c_string (name, string, len);
  vec_add1 (string_vector, name);
  return string_vector;
}

stat_segment_data_t *
stat_segment_dump_entry_r (uint32_t index, stat_client_main_t * sm)
{
  stat_segment_directory_entry_t *ep;
  stat_segment_data_t *res = 0;
  stat_segment_access_t sa;

  stat_segment_access_start (&sa, sm);

  /* Collect counter */
  ep = vec_elt_at_index (sm->directory_vector, index);
  vec_add1 (res, copy_data (ep, sm));

  if (stat_segment_access_end (&sa, sm))
    return res;
  return 0;
}

stat_segment_data_t *
stat_segment_dump_entry (uint32_t index)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_dump_entry_r (index, sm);
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
