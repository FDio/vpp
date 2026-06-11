/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

/* vperf_test.h */

#ifndef __included_vperf_test_h__
#define __included_vperf_test_h__

#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

#define VPERF_CFG_CTRL_MAGIC	 0xfeedface
#define VPERF_CFG_TXBUF_SIZE_DEF 8192
#define VPERF_CFG_RXBUF_SIZE_DEF (64 * VPERF_CFG_TXBUF_SIZE_DEF)
#define VPERF_CFG_NUM_WRITES_DEF 1000000

#define VPERF_TOKEN_HELP	  "#H"
#define VPERF_TOKEN_EXIT	  "#X"
#define VPERF_TOKEN_VERBOSE	  "#V"
#define VPERF_TOKEN_TXBUF_SIZE	  "#T:"
#define VPERF_TOKEN_NUM_TEST_SESS "#I:"
#define VPERF_TOKEN_NUM_WRITES	  "#N:"
#define VPERF_TOKEN_RXBUF_SIZE	  "#R:"
#define VPERF_TOKEN_SHOW_CFG	  "#C"
#define VPERF_TOKEN_RUN_UNI	  "#U"
#define VPERF_TOKEN_RUN_BI	  "#B"

#define VPERF_SEPARATOR_STRING "  -----------------------------\n"

#define VPERF_CTRL_HANDLE (~0)

typedef enum
{
  VPERF_CMD_SYNC,
  VPERF_CMD_START,
  VPERF_CMD_STOP,
} vperf_cmd_t;

typedef enum
{
  VPERF_TEST_TYPE_NONE,
  VPERF_TEST_TYPE_ECHO,
  VPERF_TEST_TYPE_UNI,
  VPERF_TEST_TYPE_BI,
  VPERF_TEST_TYPE_EXIT,
  VPERF_TEST_TYPE_EXIT_CLIENT,
} vperf_test_t;

typedef enum
{
  VPERF_PARAM_NONE,
  VPERF_PARAM_SERVER_RST_STREAM,
  VPERF_PARAM_CLIENT_RST_STREAM,
  VPERF_PARAM_SERVER_CLOSE_CONN,
  VPERF_PARAM_CLIENT_CLOSE_CONN,
} vperf_param_t;

typedef struct __attribute__ ((packed))
{
  uint32_t magic;
  uint32_t seq_num;
  uint32_t test;
  uint32_t test_param;
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
  union
  {
    uint64_t num_writes;
    uint64_t num_reads;
  };
  uint64_t total_bytes;
  uint32_t test_bytes;
} vperf_cfg_t;

static inline char *
vperf_test_type_str (vperf_test_t t)
{
  switch (t)
    {
    case VPERF_TEST_TYPE_NONE:
      return "NONE";

    case VPERF_TEST_TYPE_ECHO:
      return "ECHO";

    case VPERF_TEST_TYPE_UNI:
      return "UNI";

    case VPERF_TEST_TYPE_BI:
      return "BI";

    case VPERF_TEST_TYPE_EXIT:
      return "EXIT";

    case VPERF_TEST_TYPE_EXIT_CLIENT:
      return "EXIT-CLIENT";

    default:
      return "Unknown";
    }
}

static inline char *
vperf_param_str (vperf_param_t p)
{
  switch (p)
    {
    case VPERF_PARAM_NONE:
      return "NONE";

    case VPERF_PARAM_SERVER_RST_STREAM:
      return "SERVER-RST-STREAM";

    case VPERF_PARAM_CLIENT_RST_STREAM:
      return "CLIENT-RST-STREAM";

    default:
      return "Unknown";
    }
}

static inline int
vperf_cfg_verify (vperf_cfg_t *cfg, vperf_cfg_t *valid_cfg)
{
  /* Note: txbuf & rxbuf on server are the same buffer,
   *       so txbuf_size is not included in this check.
   */
  return ((cfg->magic == valid_cfg->magic) && (cfg->test == valid_cfg->test) &&
	  (cfg->verbose == valid_cfg->verbose) && (cfg->rxbuf_size == valid_cfg->rxbuf_size) &&
	  (cfg->num_writes == valid_cfg->num_writes) &&
	  (cfg->total_bytes == valid_cfg->total_bytes));
}

static inline void
vperf_cfg_init (vperf_cfg_t *cfg)
{
  cfg->magic = VPERF_CFG_CTRL_MAGIC;
  cfg->test = VPERF_TEST_TYPE_UNI;
  cfg->ctrl_handle = ~0;
  cfg->num_test_sessions = 1;
  cfg->num_test_sessions_perq = 1;
  cfg->verbose = 0;
  cfg->rxbuf_size = VPERF_CFG_RXBUF_SIZE_DEF;
  cfg->num_writes = VPERF_CFG_NUM_WRITES_DEF;
  cfg->txbuf_size = VPERF_CFG_TXBUF_SIZE_DEF;
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
  cfg->test_bytes = 0;
}

static inline char *
vperf_cmd_to_str (int cmd)
{
  switch (cmd)
    {
    case VPERF_CMD_SYNC:
      return "SYNC";
    case VPERF_CMD_START:
      return "START";
    case VPERF_CMD_STOP:
      return "STOP";
    }
  return "";
}

static inline void
vperf_cfg_dump (vperf_cfg_t *cfg, uint8_t is_client)
{
  char *spc = "     ";

  printf (
    "  test config (%p):\n" VPERF_SEPARATOR_STRING "               command: %s\n"
    "                 magic:  0x%08x\n"
    "               seq_num:  0x%08x\n"
    "            test bytes:  %s\n"
    "%-5s             test:  %s (%d)\n"
    "  additional parameter:  %s (%d)\n"
    "           ctrl handle:  %d (0x%x)\n"
    "%-5s num test sockets:  %u (0x%08x)\n"
    "%-5s          verbose:  %s (%d)\n"
    "%-5s       rxbuf size:  %lu (0x%08lx)\n"
    "%-5s       txbuf size:  %lu (0x%08lx)\n"
    "%-5s       num writes:  %lu (0x%08lx)\n"
    "       client tx bytes:  %lu (0x%08lx)\n" VPERF_SEPARATOR_STRING,
    (void *) cfg, vperf_cmd_to_str (cfg->cmd), cfg->magic, cfg->seq_num,
    cfg->test_bytes ? "yes" : "no",
    is_client && (cfg->test == VPERF_TEST_TYPE_UNI) ? "'" VPERF_TOKEN_RUN_UNI "'" :
    is_client && (cfg->test == VPERF_TEST_TYPE_BI)  ? "'" VPERF_TOKEN_RUN_BI "'" :
						      spc,
    vperf_test_type_str (cfg->test), cfg->test, vperf_param_str (cfg->test_param), cfg->test_param,
    cfg->ctrl_handle, cfg->ctrl_handle, is_client ? "'" VPERF_TOKEN_NUM_TEST_SESS "'" : spc,
    cfg->num_test_sessions, cfg->num_test_sessions, is_client ? "'" VPERF_TOKEN_VERBOSE "'" : spc,
    cfg->verbose ? "on" : "off", cfg->verbose, is_client ? "'" VPERF_TOKEN_RXBUF_SIZE "'" : spc,
    cfg->rxbuf_size, cfg->rxbuf_size, is_client ? "'" VPERF_TOKEN_TXBUF_SIZE "'" : spc,
    cfg->txbuf_size, cfg->txbuf_size, is_client ? "'" VPERF_TOKEN_NUM_WRITES "'" : spc,
    cfg->num_writes, cfg->num_writes, cfg->total_bytes, cfg->total_bytes);
}

static inline u16
vperf_make_data_port (u16 p)
{
  p = clib_net_to_host_u16 (p);
  return clib_host_to_net_u16 (p + 1);
}

static inline void
vperf_app_session_init_ (app_session_t *as, session_t *s)
{
  as->rx_fifo = s->rx_fifo;
  as->tx_fifo = s->tx_fifo;
  as->vpp_evt_q = session_main_get_vpp_event_queue (s->thread_index);
  if (session_get_transport_proto (s) == TRANSPORT_PROTO_UDP)
    {
      transport_connection_t *tc;
      tc = session_get_transport (s);
      clib_memcpy_fast (&as->transport, tc, sizeof (as->transport));
      as->is_dgram = 1;
    }
}

#define vperf_app_session_init(_as, _s) vperf_app_session_init_ ((app_session_t *) (_as), (_s))

#endif /* __included_vperf_test_h__ */
