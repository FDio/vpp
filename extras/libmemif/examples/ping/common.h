/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef _COMMON_H_
#define _COMMON_H_

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <ctype.h>
#include <libmemif.h>

#define APP_NAME "Ping"



typedef enum _log_type
{ INFO_TYPE = 1, DEBUG_TYPE = 2 } log_type;

void ping_log (log_type type, const char *format, ...);

#ifdef ICMP_DBG

#define DBG(format, ...) do {                                                                     \
ping_log(DEBUG_TYPE, "PING_DBG:%s:%s:%d: " format,  __FILE__, __func__, __LINE__ ,##__VA_ARGS__); \
} while (0)

#define LOG(...) do {                                                                             \
if (enable_log) {                                                                                 \
dprintf (out_fd, __VA_ARGS__);                                                                    \
dprintf (out_fd, "\n");                                                                           \
}                                                                                                 \
} while (0)
#define LOG_FILE "/tmp/memif_time_test.txt"
#else
#define DBG(...)
#define LOG(...)
#endif

#define INFO(...) do {                                                                            \
ping_log(INFO_TYPE, __VA_ARGS__);                                                                 \
} while (0)


#define MAX_CONNS       50
#define MAX_ITM_BRIDGE (MAX_CONNS / 2)

struct _itms_bridge
{
  struct _table
  {
/* stored indexes of connections, which must be routed */
    uint16_t idx_conn[MAX_ITM_BRIDGE];

/* count of stored indexes */
    uint16_t cnt_items;

/* numeric identifier of domain */
    uint32_t id_domain;
  }
  table[MAX_ITM_BRIDGE];

/* count of domains */
  uint8_t cnt_domain;
};

extern struct _itms_bridge itms_bridge;

typedef struct
{
/* is used for store parameters from parser and setting of connection */
  memif_conn_args_t args;

/* pointer in socket name */
  char *sock_name;

/* inform, whether id of connection is set explicitly */
  uint8_t id_is_expl;

/* inform, whether qid 0 be start in polling or interrupt mode */
  uint8_t set_q0_poll;

/* specific cpu affinity */
  cpu_set_t q0_corelist;

/* inform, whether interface is connected */
  volatile uint8_t is_connected;

/* index for identify specific instance in array */
  long index;

/* current count of available queue */
  uint8_t current_cnt_q;

/* memif conenction handle */
  memif_conn_handle_t conn;

/* index into domain table */
  int idx_domain;

/* interface ip address */
  uint8_t ip_src[4];
} memif_connection_t;

/* count of all valid connection inserted from command line */
extern int cnt_conn;

extern memif_connection_t memif_connections[MAX_CONNS];


#endif /* _COMMON_H_ */
