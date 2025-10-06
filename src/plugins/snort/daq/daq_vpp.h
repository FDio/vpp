/*
** Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software Foundation, Inc.
** 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __DAQ_VPP_H__
#define __DAQ_VPP_H__

#include <stdint.h>
#include <daq_module_api.h>
#include <snort/daq_vpp_shared.h>

#define __unused     __attribute__ ((unused))
#define __aligned(x) __attribute__ ((__aligned__ (x)))
#if __x86_64__
#define VPP_DAQ_PAUSE() __builtin_ia32_pause ()
#elif defined(__aarch64__) || defined(__arm__)
#define VPP_DAQ_PAUSE() __asm__ ("yield")
#else
#define VPP_DAQ_PAUSE()
#endif
#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))

#define DEBUG(fmt, ...)                                                       \
  if (daq_vpp_main.debug)                                                     \
    printf ("%s: %s: " fmt "\n", "daq_vpp", __func__, ##__VA_ARGS__);

/* dump.c */
char *daq_vpp_dump_pkt_hdr (const DAQ_PktHdr_t *hdr);
void daq_vpp_dump_msg_type (DAQ_MsgType type);
void daq_vpp_dump_msg (DAQ_Msg_h msg);
char *daq_vpp_dump_packet_data (const uint8_t *data, uint32_t len);
const char *daq_vpp_inject_direction (int reverse);

#define DEBUG2(fmt, ...)                                                      \
  if (daq_vpp_main.debug_msg)                                                 \
    printf ("%s: %s: " fmt "\n", "daq_vpp", __func__, ##__VA_ARGS__);

#define DEBUG_DUMP_MSG(msg)                                                   \
  if (daq_vpp_main.debug_msg)                                                 \
    {                                                                         \
      printf ("%s: %s: MSG DUMP START \n", "daq_vpp", __func__);              \
      if (msg)                                                                \
	daq_vpp_dump_msg (msg);                                               \
      printf ("%s: %s: MSG DUMP END \n", "daq_vpp", __func__);                \
    }

#define DEBUG_DUMP_DATA_HEX(data, len)                                        \
  if (daq_vpp_main.debug_msg)                                                 \
    {                                                                         \
      printf ("%s: %s: MSG DUMP START \n", "daq_vpp", __func__);              \
      char *data_buf = daq_vpp_dump_packet_data (data, len);                  \
      if (data_buf)                                                           \
	{                                                                     \
	  printf ("%s", data_buf);                                            \
	  free (data_buf);                                                    \
	}                                                                     \
      printf ("%s: %s: MSG DUMP END \n", "daq_vpp", __func__);                \
    }

#define DEBUG_DUMP_MSG2(hdr, type, data, len)                                 \
  if (daq_vpp_main.debug_msg)                                                 \
    {                                                                         \
      printf ("%s: %s: MSG DUMP START \n", "daq_vpp", __func__);              \
      char *pkt_hdr_buf = daq_vpp_dump_pkt_hdr (hdr);                         \
      char *data_buf = daq_vpp_dump_packet_data (data, len);                  \
      if (pkt_hdr_buf)                                                        \
	{                                                                     \
	  printf ("%s", pkt_hdr_buf);                                         \
	  free (pkt_hdr_buf);                                                 \
	}                                                                     \
      daq_vpp_dump_msg_type (type);                                           \
      if (data_buf)                                                           \
	{                                                                     \
	  printf ("%s", data_buf);                                            \
	  free (data_buf);                                                    \
	}                                                                     \
      printf ("%s: %s: MSG DUMP END \n", "daq_vpp", __func__);                \
    }

#define SET_ERROR(modinst, ...)                                               \
  daq_vpp_main.daq_base_api.set_errbuf (modinst, __VA_ARGS__)

typedef struct
{
  int fd;
  uint64_t size;
  void *base;
} daq_vpp_buffer_pool_t;

typedef struct _vpp_qpair
{
  daq_vpp_qpair_header_t *hdr;
  daq_vpp_desc_index_t *enq_ring;
  daq_vpp_desc_index_t *deq_ring;
  daq_vpp_desc_index_t *ebuf_ring;
  daq_vpp_head_tail_t tail;
  daq_vpp_head_tail_t ebuf_tail;
  uint16_t queue_size;
  uint16_t ebuf_queue_size;
  int enq_fd;
  int deq_fd;
  daq_vpp_input_index_t input_index;
  uint16_t used_by_instance;
  daq_vpp_qpair_id_t qpair_id;
} __aligned (64) daq_vpp_qpair_t;

typedef struct daq_vpp_msg_pool_entry
{
  DAQ_Msg_t msg;
  DAQ_PktHdr_t pkthdr;
  daq_vpp_desc_index_t index;
  union
  {
    struct daq_vpp_msg_pool_entry *freelist_next;
    daq_vpp_qpair_t *qpair;
  };
} daq_vpp_msg_pool_entry_t;

typedef struct daq_vpp_input_t
{
  /* shared memory */
  uint64_t shm_size;
  void *shm_base;
  int shm_fd;

  /* queue pairs */
  uint16_t num_qpairs;

  char name[DAQ_VPP_MAX_INST_NAME_LEN];
  daq_vpp_qpair_t qpairs[];
} daq_vpp_input_t;

typedef struct _vpp_context
{
  /* state */
  DAQ_ModuleInstance_h modinst;
  uint16_t instance_id;
  uint8_t interrupted;
  int timeout;

  /* stats */
  DAQ_Stats_t stats;

  /* epoll and eventfd */
  int epoll_fd;
  int wakeup_fd;

  uint16_t num_qpairs;
  daq_vpp_qpair_index_t next_qpair;
  daq_vpp_qpair_t **qpairs;

  /* msg pool */
  DAQ_MsgPoolInfo_t msg_pool_info;
  daq_vpp_msg_pool_entry_t *msg_pool_freelist;
  daq_vpp_msg_pool_entry_t msg_pool[];
} daq_vpp_ctx_t;

typedef struct
{
  uint32_t debug : 1;
  uint32_t debug_msg : 1;
  uint32_t config_parsed : 1;
  uint32_t connected : 1;
  uint32_t buffer_pools_initialized : 1;
  uint32_t hangup : 1;

  /* configured */
  uint32_t default_msg_pool_size;
  DAQ_BaseAPI_t daq_base_api;

  /* buffer pools */
  uint8_t num_bpools;
  daq_vpp_buffer_pool_t *bpools;

  /* socket */
  int socket_fd;
  const char *socket_name;

  /* inputs */
  daq_vpp_input_t **inputs;
  uint16_t n_inputs;

  /* instances */
  uint16_t n_instances;
} daq_vpp_main_t;

extern daq_vpp_main_t daq_vpp_main;

/* main.c */
int daq_vpp_err (daq_vpp_ctx_t *ctx, char *fmt, ...);

/* config.c */
int daq_vpp_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table);
int daq_vpp_parse_config (daq_vpp_ctx_t *ctx, DAQ_ModuleConfig_h modcfg);

/* socket.c */
int daq_vpp_connect (daq_vpp_ctx_t *ctx, uint16_t num_instances,
		     DAQ_Mode mode);
int daq_vpp_find_or_add_input (daq_vpp_ctx_t *ctx, char *name,
			       daq_vpp_input_t **inp);

#endif /* __DAQ_VPP_H__ */
