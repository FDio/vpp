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
#include <stdatomic.h>
#include <vpp/stats/stat_segment.h>
#include <vpp-api/client/stat_client.h>

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
  return stat_segment_adjust (sm,
			      (void *) sm->shared_header->directory_vector);
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
      close (mfd);
      perror ("mmap fstat failed");
      return -4;
    }
  if ((memaddr =
       mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, mfd, 0)) == MAP_FAILED)
    {
      close (mfd);
      perror ("mmap map failed");
      return -5;
    }

  close (mfd);
  sm->memory_size = st.st_size;
  sm->shared_header = memaddr;
  sm->directory_vector =
    stat_segment_adjust (sm, (void *) sm->shared_header->directory_vector);

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
  stat_segment_access_t sa;
  stat_segment_directory_entry_t *ep;

  /* Has directory been update? */
  if (sm->shared_header->epoch != sm->current_epoch)
    return 0;
  if (stat_segment_access_start (&sa, sm))
    return 0;
  ep = vec_elt_at_index (sm->directory_vector, STAT_COUNTER_HEARTBEAT);
  if (!stat_segment_access_end (&sa, sm))
    return 0.0;
  return ep->value;
}

double
stat_segment_heartbeat (void)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_heartbeat_r (sm);
}

#define stat_vec_dup(S,V)                             \
  ({                                                  \
  __typeof__ ((V)[0]) * _v(v) = 0;                    \
  if (V && ((void *)V > (void *)S->shared_header) &&  \
      (((void*)V + vec_bytes(V)) <                    \
       ((void *)S->shared_header + S->memory_size)))  \
    _v(v) = vec_dup(V);                               \
   _v(v);                                             \
})

static stat_segment_data_t
copy_data (stat_segment_directory_entry_t * ep, stat_client_main_t * sm)
{
  stat_segment_data_t result = { 0 };
  int i;
  vlib_counter_t **combined_c;	/* Combined counter */
  counter_t **simple_c;		/* Simple counter */
  uint64_t *error_vector;
  stat_segment_directory_entry_t *directory_vector;
  stat_segment_directory_entry_t *symlink_counter;
  stat_segment_symlink_entry_t *symlink_vector, *symlink;

  assert (sm->shared_header);

  result.type = ep->type;
  result.name = strdup (ep->name);
  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      result.scalar_value = ep->value;
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      simple_c = stat_segment_adjust (sm, ep->data);
      result.simple_counter_vec = stat_vec_dup (sm, simple_c);
      for (i = 0; i < vec_len (simple_c); i++)
	{
	  counter_t *cb = stat_segment_adjust (sm, simple_c[i]);
	  result.simple_counter_vec[i] = stat_vec_dup (sm, cb);
	}
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      combined_c = stat_segment_adjust (sm, ep->data);
      result.combined_counter_vec = stat_vec_dup (sm, combined_c);
      for (i = 0; i < vec_len (combined_c); i++)
	{
	  vlib_counter_t *cb = stat_segment_adjust (sm, combined_c[i]);
	  result.combined_counter_vec[i] = stat_vec_dup (sm, cb);
	}
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      /* Gather errors from all threads into a vector */
      error_vector =
	stat_segment_adjust (sm, (void *) sm->shared_header->error_vector);
      vec_validate (result.error_vector, vec_len (error_vector) - 1);
      for (i = 0; i < vec_len (error_vector); i++)
	{
	  counter_t *cb = stat_segment_adjust (sm, (void *) error_vector[i]);
	  result.error_vector[i] = cb[ep->index];
	}
      break;

    case STAT_DIR_TYPE_NAME_VECTOR:
      {
	uint8_t **name_vector = stat_segment_adjust (sm, ep->data);
	result.name_vector = stat_vec_dup (sm, name_vector);
	for (i = 0; i < vec_len (name_vector); i++)
	  {
	    u8 *name = stat_segment_adjust (sm, name_vector[i]);
	    result.name_vector[i] = stat_vec_dup (sm, name);
	  }
      }
      break;

    case STAT_DIR_TYPE_SYMLINK:
      /* Gather info from all threads into a vector */
      symlink_vector =
	stat_segment_adjust (sm, (void *) sm->shared_header->symlink_vector);
      symlink = vec_elt_at_index (symlink_vector, ep->index);
      directory_vector = get_stat_vector_r (sm);
      symlink_counter = &directory_vector[symlink->counter_index];

      result.symlink_type = symlink_counter->type;
      switch (symlink_counter->type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  simple_c = stat_segment_adjust (sm, symlink_counter->data);
	  vec_validate (result.simple_counter_vec, 0);
	  vec_validate (result.simple_counter_vec[0], vec_len (simple_c) - 1);
	  for (i = 0; i < vec_len (simple_c); i++)
	    {
	      counter_t *cb = stat_segment_adjust (sm, simple_c[i]);
	      result.simple_counter_vec[0][i] = cb[symlink->vec_index];
	    }
	  break;
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  combined_c = stat_segment_adjust (sm, symlink_counter->data);
	  vec_validate (result.combined_counter_vec, 0);
	  vec_validate (result.combined_counter_vec[0],
			vec_len (combined_c) - 1);
	  for (i = 0; i < vec_len (combined_c); i++)
	    {
	      vlib_counter_t *cb = stat_segment_adjust (sm, combined_c[i]);
	      result.combined_counter_vec[0][i] = cb[symlink->vec_index];
	    }
	  break;
	default:
	  break;
	}
      break;

    case STAT_DIR_TYPE_EMPTY:
      break;

    default:
      fprintf (stderr, "Unknown type: %d\n", ep->type);
    }
  return result;
}

void
stat_segment_data_free (stat_segment_data_t * res)
{
  int i, j;
  stat_directory_type_t type;
  for (i = 0; i < vec_len (res); i++)
    {
      type = res[i].type;
      if (type == STAT_DIR_TYPE_SYMLINK)
	{
	  type = res[i].symlink_type;
	}
      switch (type)
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
	case STAT_DIR_TYPE_NAME_VECTOR:
	  for (j = 0; j < vec_len (res[i].name_vector); j++)
	    vec_free (res[i].name_vector[j]);
	  vec_free (res[i].name_vector);
	  break;
	case STAT_DIR_TYPE_ERROR_INDEX:
	  vec_free (res[i].error_vector);
	  break;
	case STAT_DIR_TYPE_SCALAR_INDEX:
	  break;
	default:
	  assert (0);
	}
      free (res[i].name);
    }
  vec_free (res);
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

  if (stat_segment_access_start (&sa, sm))
    return 0;

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

  if (stat_segment_access_start (&sa, sm))
    return 0;

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

  if (stat_segment_access_start (&sa, sm))
    return 0;

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
stat_segment_index_to_name_r (uint32_t index, stat_client_main_t * sm)
{
  stat_segment_directory_entry_t *ep;
  stat_segment_access_t sa;
  stat_segment_directory_entry_t *vec;

  /* Has directory been update? */
  if (sm->shared_header->epoch != sm->current_epoch)
    return 0;
  if (stat_segment_access_start (&sa, sm))
    return 0;
  vec = get_stat_vector_r (sm);
  ep = vec_elt_at_index (vec, index);
  if (!stat_segment_access_end (&sa, sm))
    return 0;
  return strdup (ep->name);
}

char *
stat_segment_index_to_name (uint32_t index)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_index_to_name_r (index, sm);
}

uint64_t
stat_segment_version_r (stat_client_main_t * sm)
{
  ASSERT (sm->shared_header);
  return sm->shared_header->version;
}

uint64_t
stat_segment_version (void)
{
  stat_client_main_t *sm = &stat_client_main;
  return stat_segment_version_r (sm);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
