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

#include <libmemif.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef ICMP_DBG
#define DBG(...)                                                              \
  do                                                                          \
    {                                                                         \
      printf (APP_NAME ":%s:%d: ", __func__, __LINE__);                       \
      printf (__VA_ARGS__);                                                   \
      printf ("\n");                                                          \
    }                                                                         \
  while (0)
#else
#define DBG(...)
#endif

#define INFO(...)                                                             \
  do                                                                          \
    {                                                                         \
      printf ("INFO: " __VA_ARGS__);                                          \
      printf ("\n");                                                          \
    }                                                                         \
  while (0)

/* maximum tx/rx memif buffers */
#define MAX_MEMIF_BUFS 256

struct memif_connection;

typedef int (memif_packet_handler_t) (struct memif_connection *conn);

typedef int (packet_generator_t) (struct memif_connection *c,
				  uint16_t num_pkts);

typedef struct memif_connection
{
  uint16_t index;
  /* memif conenction handle */
  memif_conn_handle_t conn;
  uint8_t is_connected;
  /* transmit queue id */
  uint16_t tx_qid;
  /* tx buffers */
  memif_buffer_t *tx_bufs;
  /* allocated tx buffers counter */
  /* number of tx buffers pointing to shared memory */
  uint16_t tx_buf_num;
  /* rx buffers */
  memif_buffer_t *rx_bufs;
  /* allcoated rx buffers counter */
  /* number of rx buffers pointing to shared memory */
  uint16_t rx_buf_num;
  memif_packet_handler_t *packet_handler;
  /* interface ip address */
  uint8_t ip_addr[4];
  /* interface hw address */
  uint8_t hw_addr[6];
} memif_connection_t;

void print_version ();

int parse_ip4 (const char *input, uint8_t out[4]);

int parse_mac (const char *input, uint8_t out[6]);

void alloc_memif_buffers (memif_connection_t *c);

void free_memif_buffers (memif_connection_t *c);

void print_memif_details (memif_connection_t *c);

void print_memif_rx_ring_details (memif_connection_t *c, uint16_t qid);

void print_memif_tx_ring_details (memif_connection_t *c, uint16_t qid);

int send_packets (memif_connection_t *conn, uint16_t qid,
		  packet_generator_t *gen, uint32_t num_pkts,
		  uint16_t max_pkt_size);

/* Expect packets smaller than 2048b */
int responder (memif_conn_handle_t conn, void *private_ctx, uint16_t qid);

/* Expect packets smaller than 2048b */
int responder_zero_copy (memif_conn_handle_t conn, void *private_ctx,
			 uint16_t qid);

/* reply with the same data */
int basic_packet_handler (memif_connection_t *conn);

/* ICMPv4 and ARP handler */
int icmp_packet_handler (memif_connection_t *conn);

#endif /* COMMON_H */