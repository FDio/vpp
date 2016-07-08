/*
 *------------------------------------------------------------------
 * persist.c - persistent data structure storage test / demo code
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/serialize.h>
#include <svmdb.h>

typedef struct
{
  svmdb_client_t *c;
} persist_main_t;

persist_main_t persist_main;

typedef struct
{
  u8 *string1;
  u8 *string2;
} demo_struct2_t;

typedef struct
{
  demo_struct2_t *demo2;
  u8 *name;
} demo_struct1_t;

/*
 * Data structures in persistent shared memory, all the time
 */
clib_error_t *
persist_malloc (persist_main_t * pm)
{
  demo_struct2_t *demo2;
  demo_struct1_t *demo1;
  time_t starttime = time (0);
  char *datestring = ctime (&starttime);
  void *oldheap;

  /* Get back the root pointer */
  demo1 = svmdb_local_get_variable_reference
    (pm->c, SVMDB_NAMESPACE_VEC, "demo1_location");

  /* It doesnt exist create our data structures */
  if (demo1 == 0)
    {
      /* If you want MP / thread safety, lock the region... */
      pthread_mutex_lock (&pm->c->db_rp->mutex);

      /* Switch to the shared memory region heap */
      oldheap = svm_push_data_heap (pm->c->db_rp);

      /* Allocate the top-level structure as a single element vector */
      vec_validate (demo1, 0);

      /* Allocate the next-level structure as a plain old memory obj */
      demo2 = clib_mem_alloc (sizeof (*demo2));

      demo1->demo2 = demo2;
      demo1->name = format (0, "My name is Ishmael%c", 0);
      demo2->string1 = format (0, "Here is string1%c", 0);
      demo2->string2 = format (0, "Born at %s%c", datestring, 0);

      /* Back to the process-private heap */
      svm_pop_heap (oldheap);
      pthread_mutex_unlock (&pm->c->db_rp->mutex);

      /*
       * Set the root pointer. Note: this guy switches heaps, locks, etc.
       * We allocated demo1 as a vector to make this "just work..."
       */
      svmdb_local_set_vec_variable (pm->c, "demo1_location",
				    demo1, sizeof (demo1));

    }
  else
    {
      /* retrieve and print data from shared memory */
      demo2 = demo1->demo2;
      fformat (stdout, "name: %s\n", demo1->name);
      fformat (stdout, "demo2 location: %llx\n", demo2);
      fformat (stdout, "string1: %s\n", demo2->string1);
      fformat (stdout, "string2: %s\n", demo2->string2);
    }
  return 0;
}

void
unserialize_demo1 (serialize_main_t * sm, va_list * args)
{
  demo_struct1_t **result = va_arg (*args, demo_struct1_t **);
  demo_struct1_t *demo1;
  demo_struct2_t *demo2;

  /* Allocate data structures in process private memory */
  demo1 = clib_mem_alloc (sizeof (*demo1));
  demo2 = clib_mem_alloc (sizeof (*demo2));
  demo1->demo2 = demo2;

  /* retrieve data from shared memory checkpoint */
  unserialize_cstring (sm, (char **) &demo1->name);
  unserialize_cstring (sm, (char **) &demo2->string1);
  unserialize_cstring (sm, (char **) &demo2->string2);
  *result = demo1;
}

void
serialize_demo1 (serialize_main_t * sm, va_list * args)
{
  demo_struct1_t *demo1 = va_arg (*args, demo_struct1_t *);
  demo_struct2_t *demo2 = demo1->demo2;

  serialize_cstring (sm, (char *) demo1->name);
  serialize_cstring (sm, (char *) demo2->string1);
  serialize_cstring (sm, (char *) demo2->string2);
}

/* Serialize / unserialize variant */
clib_error_t *
persist_serialize (persist_main_t * pm)
{
  u8 *checkpoint;
  serialize_main_t sm;

  demo_struct2_t *demo2;
  demo_struct1_t *demo1;
  time_t starttime = time (0);
  char *datestring = ctime (&starttime);

  /* Get back the root pointer */
  checkpoint = svmdb_local_get_vec_variable (pm->c, "demo1_checkpoint",
					     sizeof (u8));

  /* It doesnt exist create our data structures */
  if (checkpoint == 0)
    {
      /* Allocate data structures in process-private memory */
      demo1 = clib_mem_alloc (sizeof (*demo2));
      vec_validate (demo1, 0);
      demo2 = clib_mem_alloc (sizeof (*demo2));

      demo1->demo2 = demo2;
      demo1->name = format (0, "My name is Ishmael%c", 0);
      demo2->string1 = format (0, "Here is string1%c", 0);
      demo2->string2 = format (0, "Born at %s%c", datestring, 0);

      /* Create checkpoint */
      serialize_open_vector (&sm, checkpoint);
      serialize (&sm, serialize_demo1, demo1);
      checkpoint = serialize_close_vector (&sm);

      /* Copy checkpoint into shared memory */
      svmdb_local_set_vec_variable (pm->c, "demo1_checkpoint",
				    checkpoint, sizeof (u8));
      /* Toss the process-private-memory original.. */
      vec_free (checkpoint);
    }
  else
    {
      /* Open the checkpoint */
      unserialize_open_data (&sm, checkpoint, vec_len (checkpoint));
      unserialize (&sm, unserialize_demo1, &demo1);

      /* Toss the process-private-memory checkpoint copy */
      vec_free (checkpoint);

      /* Off we go... */
      demo2 = demo1->demo2;
      fformat (stdout, "name: %s\n", demo1->name);
      fformat (stdout, "demo2 location: %llx\n", demo2);
      fformat (stdout, "string1: %s\n", demo2->string1);
      fformat (stdout, "string2: %s\n", demo2->string2);
    }
  return 0;
}


int
main (int argc, char **argv)
{
  unformat_input_t _input, *input = &_input;
  persist_main_t *pm = &persist_main;
  clib_error_t *error = 0;

  /* Make a 4mb database arena, chroot so it's truly private */
  pm->c = svmdb_map_chroot_size ("/ptest", 4 << 20);

  ASSERT (pm->c);

  unformat_init_command_line (input, argv);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "malloc"))
	error = persist_malloc (pm);
      else if (unformat (input, "serialize"))
	error = persist_serialize (pm);
      else
	{
	  error = clib_error_return (0, "Unknown flavor '%U'",
				     format_unformat_error, input);
	  break;
	}
    }

  svmdb_unmap (pm->c);

  if (error)
    {
      clib_error_report (error);
      exit (1);
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
