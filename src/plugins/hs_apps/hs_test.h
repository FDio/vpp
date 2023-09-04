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

#define HS_TEST_CFG_CTRL_MAGIC	   0xfeedface
#define HS_TEST_CFG_TXBUF_SIZE_DEF 8192
#define HS_TEST_CFG_RXBUF_SIZE_DEF (64 * HS_TEST_CFG_TXBUF_SIZE_DEF)
#define HS_TEST_CFG_NUM_WRITES_DEF 1000000

#define VCL_TEST_TOKEN_HELP	     "#H"
#define VCL_TEST_TOKEN_EXIT	     "#X"
#define VCL_TEST_TOKEN_VERBOSE	     "#V"
#define VCL_TEST_TOKEN_TXBUF_SIZE    "#T:"
#define VCL_TEST_TOKEN_NUM_TEST_SESS "#I:"
#define VCL_TEST_TOKEN_NUM_WRITES    "#N:"
#define VCL_TEST_TOKEN_RXBUF_SIZE    "#R:"
#define VCL_TEST_TOKEN_SHOW_CFG	     "#C"
#define HS_TEST_TOKEN_RUN_UNI	     "#U"
#define HS_TEST_TOKEN_RUN_BI	     "#B"

#define HS_TEST_SEPARATOR_STRING "  -----------------------------\n"

#define HS_CTRL_HANDLE (~0)

typedef enum
{
  HS_TEST_CMD_SYNC,
  HS_TEST_CMD_START,
  HS_TEST_CMD_STOP,
} hs_test_cmd_t;

typedef enum
{
  HS_TEST_TYPE_NONE,
  HS_TEST_TYPE_ECHO,
  HS_TEST_TYPE_UNI,
  HS_TEST_TYPE_BI,
  HS_TEST_TYPE_EXIT,
  HS_TEST_TYPE_EXIT_CLIENT,
} hs_test_t;

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

static inline char *
hs_test_type_str (hs_test_t t)
{
  switch (t)
    {
    case HS_TEST_TYPE_NONE:
      return "NONE";

    case HS_TEST_TYPE_ECHO:
      return "ECHO";

    case HS_TEST_TYPE_UNI:
      return "UNI";

    case HS_TEST_TYPE_BI:
      return "BI";

    case HS_TEST_TYPE_EXIT:
      return "EXIT";

    default:
      return "Unknown";
    }
}

static inline int
hs_test_cfg_verify (hs_test_cfg_t *cfg, hs_test_cfg_t *valid_cfg)
{
  /* Note: txbuf & rxbuf on server are the same buffer,
   *       so txbuf_size is not included in this check.
   */
  return ((cfg->magic == valid_cfg->magic) && (cfg->test == valid_cfg->test) &&
	  (cfg->verbose == valid_cfg->verbose) &&
	  (cfg->rxbuf_size == valid_cfg->rxbuf_size) &&
	  (cfg->num_writes == valid_cfg->num_writes) &&
	  (cfg->total_bytes == valid_cfg->total_bytes));
}

static inline void
hs_test_cfg_init (hs_test_cfg_t *cfg)
{
  cfg->magic = HS_TEST_CFG_CTRL_MAGIC;
  cfg->test = HS_TEST_TYPE_UNI;
  cfg->ctrl_handle = ~0;
  cfg->num_test_sessions = 1;
  cfg->num_test_sessions_perq = 1;
  cfg->verbose = 0;
  cfg->rxbuf_size = HS_TEST_CFG_RXBUF_SIZE_DEF;
  cfg->num_writes = HS_TEST_CFG_NUM_WRITES_DEF;
  cfg->txbuf_size = HS_TEST_CFG_TXBUF_SIZE_DEF;
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
}

static inline char *
hs_test_cmd_to_str (int cmd)
{
  switch (cmd)
    {
    case HS_TEST_CMD_SYNC:
      return "SYNC";
    case HS_TEST_CMD_START:
      return "START";
    case HS_TEST_CMD_STOP:
      return "STOP";
    }
  return "";
}

static inline void
hs_test_cfg_dump (hs_test_cfg_t *cfg, uint8_t is_client)
{
  char *spc = "     ";

  printf (
    "  test config (%p):\n" HS_TEST_SEPARATOR_STRING
    "               command: %s\n:"
    "                 magic:  0x%08x\n"
    "               seq_num:  0x%08x\n"
    "%-5s             test:  %s (%d)\n"
    "           ctrl handle:  %d (0x%x)\n"
    "%-5s num test sockets:  %u (0x%08x)\n"
    "%-5s          verbose:  %s (%d)\n"
    "%-5s       rxbuf size:  %lu (0x%08lx)\n"
    "%-5s       txbuf size:  %lu (0x%08lx)\n"
    "%-5s       num writes:  %lu (0x%08lx)\n"
    "       client tx bytes:  %lu (0x%08lx)\n" HS_TEST_SEPARATOR_STRING,
    (void *) cfg, hs_test_cmd_to_str (cfg->cmd), cfg->magic, cfg->seq_num,
    is_client && (cfg->test == HS_TEST_TYPE_UNI) ? "'" HS_TEST_TOKEN_RUN_UNI
						   "'" :
    is_client && (cfg->test == HS_TEST_TYPE_BI) ? "'" HS_TEST_TOKEN_RUN_BI
						  "'" :
							spc,
    hs_test_type_str (cfg->test), cfg->test, cfg->ctrl_handle,
    cfg->ctrl_handle, is_client ? "'" VCL_TEST_TOKEN_NUM_TEST_SESS "'" : spc,
    cfg->num_test_sessions, cfg->num_test_sessions,
    is_client ? "'" VCL_TEST_TOKEN_VERBOSE "'" : spc,
    cfg->verbose ? "on" : "off", cfg->verbose,
    is_client ? "'" VCL_TEST_TOKEN_RXBUF_SIZE "'" : spc, cfg->rxbuf_size,
    cfg->rxbuf_size, is_client ? "'" VCL_TEST_TOKEN_TXBUF_SIZE "'" : spc,
    cfg->txbuf_size, cfg->txbuf_size,
    is_client ? "'" VCL_TEST_TOKEN_NUM_WRITES "'" : spc, cfg->num_writes,
    cfg->num_writes, cfg->total_bytes, cfg->total_bytes);
}

#endif /* __included_hs_test_t__ */
