/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/*
 * dump_metrics_test.c
 */
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/mem.h>

#include <vlib/vlib.h>
#include <vlib/main.h>
#include "dump_metrics.h"

typedef struct
{
  const char *res;
  const char *id;
} test_data_t;

test_data_t test_data[] = {
  { .res =
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"0\"} 42\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"1\"} 43\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"2\"} 44\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"3\"} 45\n",
    .id = "/interfaces/GigabitEthernet0_13_0.100/drops" },
  { .res =
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"0\"} 42\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"1\"} 43\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"2\"} 44\n"
      "interfaces_drops{interface=\"GigabitEthernet0_13_0.100\",index=\"0\",thread=\"3\"} 45\n",
    .id = "/interfaces/GigabitEthernet0/13/0.100/drops" },
  { .res =
      "interfaces_drops{interface=\"GigabitEthernet0:13:0.100\",index=\"0\",thread=\"0\"} 42\n"
      "interfaces_drops{interface=\"GigabitEthernet0:13:0.100\",index=\"0\",thread=\"1\"} 43\n"
      "interfaces_drops{interface=\"GigabitEthernet0:13:0.100\",index=\"0\",thread=\"2\"} 44\n"
      "interfaces_drops{interface=\"GigabitEthernet0:13:0.100\",index=\"0\",thread=\"3\"} 45\n",
    .id = "/interfaces/GigabitEthernet0:13:0.100/drops" },
  { .res = "nodes_vectors{node=\"MgmtLoopback0_0-rx\",index=\"0\",thread=\"0\"} 42\n"
	   "nodes_vectors{node=\"MgmtLoopback0_0-rx\",index=\"0\",thread=\"1\"} 43\n"
	   "nodes_vectors{node=\"MgmtLoopback0_0-rx\",index=\"0\",thread=\"2\"} 44\n"
	   "nodes_vectors{node=\"MgmtLoopback0_0-rx\",index=\"0\",thread=\"3\"} 45\n",
    .id = "/nodes/MgmtLoopback0_0-rx/vectors" },
};

stat_segment_data_t *test;

static void
test_print_metric_v2_basic (int testId)
{
  u8 *buf = 0;
  size_t len;
  FILE *mem = open_memstream ((char **) &buf, &len); // capture output

  // Example call – adjust args to match your function signature
  free (test->name);
  test->name = strdup (test_data[testId].id);
  printf ("Testing with ID: %s\n", test_data[testId].id);
  print_metric_v2 (mem, test);

  fclose (mem);
  printf ("Captured output:\n%s\n", buf);
  ASSERT (strncmp ((char *) buf, test_data[testId].res, strlen (test_data[testId].res)) == 0);

  // Check sanitization, quoting, etc.
  free (buf);
}

int
main (void)
{
  vlib_main_t *vm = (vlib_main_t *) &vlib_global_main;

  // Heap setup (required)
  void *heap = clib_mem_init (NULL, 256ULL << 20);
  if (!heap)
    {
      fprintf (stderr, "clib_mem_init failed\n");
      return 1;
    }
  clib_mem_set_heap (heap);

  // Minimal vm setup
  vm->thread_index = 0;

  test = malloc (sizeof (stat_segment_data_t));
  *test = (stat_segment_data_t){
    .name = strdup (""),
    .type = STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
    .via_symlink = false,
  };
  vec_validate (test->simple_counter_vec, 3); // e.g. 4 threads (indices 0..3)
  test->simple_counter_vec[0] = NULL;	      // optional: clear if needed

  // Now populate counters for each thread
  for (int thread = 0; thread < 4; thread++)
    {
      vec_validate (test->simple_counter_vec[thread], 0); // at least 1 element
      test->simple_counter_vec[thread][0] = 42 + thread;  // example value
    }
  for (int i = 0; i < sizeof (test_data) / sizeof (test_data[0]); i++)
    test_print_metric_v2_basic (i);

  printf ("All tests passed!\n");
  return 0;
}
