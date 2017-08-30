/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <main_test.h>
#include <socket_test.h>

int
on_connect (memif_conn_handle_t conn, void *ctx)
{
  return 0;
}

int
on_disconnect (memif_conn_handle_t conn, void *ctx)
{
  return 0;
}

int
on_interrupt (memif_conn_handle_t conn, void *ctx, uint16_t qid)
{
  return 0;
}

int
control_fd_update (int fd, uint8_t events)
{
  return 0;
}

int
main (void)
{
  int num_fail;
  Suite *main, *socket;
  SRunner *sr;

  main = main_suite ();
  socket = socket_suite ();

  sr = srunner_create (main);

  srunner_add_suite (sr, socket);

  srunner_run_all (sr, CK_VERBOSE);
  num_fail = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (num_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
