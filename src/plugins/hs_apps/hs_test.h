/*
 * hs_test.h
 *
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#ifndef __included_hs_test_t__
#define __included_hs_test_t__

#include <vnet/session/application_interface.h>

typedef struct __attribute__ ((packed))
{
  uint32_t magic;
  uint32_t seq_num;
  uint32_t test;
  uint32_t cmd;
  uint32_t ctrl_handle;
  uint32_t num_test_sessions;
  uint32_t num_test_sessions_perq;
  uint32_t num_test_qsessions;
  uint32_t verbose;
  uint32_t address_ip6;
  uint32_t transport_udp;
  uint64_t rxbuf_size;
  uint64_t txbuf_size;
  uint64_t num_writes;
  uint64_t total_bytes;
} hs_test_cfg_t;

#endif /* __included_hs_test_t__ */
