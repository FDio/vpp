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

#ifndef _UNIT_TEST_H_
#define _UNIT_TEST_H_

#include <stdlib.h>
#include <check.h>

#include <libmemif.h>

#define TEST_APP_NAME "unit_test_app"
#define TEST_IF_NAME  "unit_test_if"
#define TEST_SECRET   "psst"

int on_connect (memif_conn_handle_t conn, void *ctx);

int on_disconnect (memif_conn_handle_t conn, void *ctx);

int on_interrupt (memif_conn_handle_t conn, void *ctx, uint16_t qid);

int control_fd_update (int fd, uint8_t events);

#endif /* _UNIT_TEST_H_ */
