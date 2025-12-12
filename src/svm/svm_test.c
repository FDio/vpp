/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/*
 *------------------------------------------------------------------
 * svm_test.c -- brain police
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
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>

#include "svm.h"


int
main (int argc, char **argv)
{
  svm_region_t *root_rp, *rp;
  svm_map_region_args_t *a = 0;

  vec_validate (a, 0);

  root_rp = svm_region_init ();

  ASSERT (root_rp);

  a->name = "/qvnet";
  a->size = (4 << 10);

  rp = svm_region_find_or_create (root_rp, a);

  ASSERT (rp);

  *((u32 *) rp->data_base) = 0xdeadbeef;
  svm_region_unmap (root_rp, rp);

  fformat (stdout, "exiting...\n");

  exit (0);
}
