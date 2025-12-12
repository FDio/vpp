/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* pg_init.c: VLIB packet generator */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>

/* Global main structure. */
pg_main_t pg_main;

static clib_error_t *
pg_init (vlib_main_t * vm)
{
  clib_error_t *error;
  pg_main_t *pg = &pg_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads = 1 /* main thread */  + vtm->n_threads;

  pg->if_index_by_if_id = hash_create (0, sizeof (uword));

  if ((error = vlib_call_init_function (vm, vnet_main_init)))
    goto done;

  if ((error = vlib_call_init_function (vm, pg_cli_init)))
    goto done;

  vec_validate (pg->replay_buffers_by_thread, num_threads);

done:
  return error;
}

VLIB_INIT_FUNCTION (pg_init);
