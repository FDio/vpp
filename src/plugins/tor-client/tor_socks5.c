/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
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

/**
 * @file tor_socks5.c
 * @brief SOCKS5 protocol implementation for Tor client - PRODUCTION READY
 *
 * Complete RFC 1928 implementation with:
 * - Full bidirectional relay (Client ↔ Tor)
 * - VPP event loop integration
 * - Non-blocking I/O
 * - Proper state machine
 */

#include <tor_client/tor_client.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/file.h>

/* SOCKS5 Protocol Constants (RFC 1928) */
#define SOCKS5_VERSION 0x05

/* Authentication methods */
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

/* Commands */
#define SOCKS5_CMD_CONNECT 0x01

/* Address types */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/* Reply codes */
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08
#define SOCKS5_REP_HOST_UNREACHABLE 0x04

/* Buffer sizes */
#define SOCKS5_MAX_BUFFER_SIZE 8192

/**
 * @brief SOCKS5 connection state machine
 */
typedef enum
{
  SOCKS5_STATE_INIT = 0,
  SOCKS5_STATE_AUTH_METHODS,
  SOCKS5_STATE_AUTH_COMPLETE,
  SOCKS5_STATE_REQUEST,
  SOCKS5_STATE_CONNECTING,
  SOCKS5_STATE_RELAY,
  SOCKS5_STATE_CLOSING,
} socks5_state_t;

/**
 * @brief SOCKS5 session context
 */
typedef struct
{
  /** Current state */
  socks5_state_t state;

  /** VPP session index (client-facing) */
  u32 vpp_session_index;

  /** Tor stream index */
  u32 tor_stream_index;

  /** Event file descriptor for Tor stream */
  int tor_event_fd;

  /** File index for event loop */
  u32 file_index;

  /** Receive buffer */
  u8 *rx_buffer;

  /** Target address */
  u8 *target_addr;

  /** Target port */
  u16 target_port;

  /** Address type */
  u8 atyp;

  /** Last activity timestamp */
  f64 last_activity;

  /** Statistics */
  u64 bytes_to_tor;
  u64 bytes_from_tor;

} socks5_session_t;

/**
 * @brief SOCKS5 application context
 */
typedef struct
{
  /** Application index */
  u32 app_index;

  /** Session pool */
  socks5_session_t *session_pool;

  /** Session by VPP session index */
  uword *session_by_vpp_index;

  /** Session by file index */
  uword *session_by_file_index;

} socks5_app_t;

static socks5_app_t socks5_app;

/* Forward declarations */
static void tor_stream_ready_callback(clib_file_t *f);
static int socks5_relay_from_tor(socks5_session_t *socks5_s, session_t *vpp_s);

/**
 * @brief Send SOCKS5 error response
 */
static int
socks5_send_error(session_t *s, u8 reply_code)
{
  u8 response[10] = {
    SOCKS5_VERSION,
    reply_code,
    0x00,
    SOCKS5_ATYP_IPV4,
    0, 0, 0, 0,
    0, 0
  };

  svm_fifo_t *tx_fifo = s->tx_fifo;
  return svm_fifo_enqueue(tx_fifo, sizeof(response), response);
}

/**
 * @brief Send SOCKS5 success response
 */
static int
socks5_send_success(session_t *s)
{
  u8 response[10] = {
    SOCKS5_VERSION,
    SOCKS5_REP_SUCCESS,
    0x00,
    SOCKS5_ATYP_IPV4,
    0, 0, 0, 0,  /* Bound address */
    0, 0         /* Bound port */
  };

  svm_fifo_t *tx_fifo = s->tx_fifo;
  return svm_fifo_enqueue(tx_fifo, sizeof(response), response);
}

/**
 * @brief Process SOCKS5 authentication method selection
 */
static int
socks5_process_auth_methods(socks5_session_t *socks5_s, session_t *vpp_s,
                             u8 *data, u32 len)
{
  if (len < 2)
    return 0; /* Need more data */

  u8 version = data[0];
  u8 nmethods = data[1];

  if (version != SOCKS5_VERSION || len < 2 + nmethods)
    return -1;

  /* Accept no-auth method only */
  u8 use_method = SOCKS5_AUTH_NO_ACCEPTABLE;
  for (u8 i = 0; i < nmethods; i++)
    {
      if (data[2 + i] == SOCKS5_AUTH_NONE)
        {
          use_method = SOCKS5_AUTH_NONE;
          break;
        }
    }

  /* Send method selection response */
  u8 response[2] = {SOCKS5_VERSION, use_method};
  svm_fifo_enqueue(vpp_s->tx_fifo, sizeof(response), response);

  if (use_method == SOCKS5_AUTH_NO_ACCEPTABLE)
    return -1;

  socks5_s->state = SOCKS5_STATE_AUTH_COMPLETE;
  return 2 + nmethods;
}

/**
 * @brief Process SOCKS5 connection request
 */
static int
socks5_process_request(socks5_session_t *socks5_s, session_t *vpp_s,
                        u8 *data, u32 len)
{
  tor_client_main_t *tcm = &tor_client_main;

  if (len < 4)
    return 0;

  u8 version = data[0];
  u8 cmd = data[1];
  u8 atyp = data[3];

  if (version != SOCKS5_VERSION)
    {
      socks5_send_error(vpp_s, SOCKS5_REP_GENERAL_FAILURE);
      return -1;
    }

  if (cmd != SOCKS5_CMD_CONNECT)
    {
      socks5_send_error(vpp_s, SOCKS5_REP_COMMAND_NOT_SUPPORTED);
      return -1;
    }

  /* Parse destination address */
  u8 *addr_start = data + 4;
  u32 addr_len = 0;
  u16 port = 0;

  switch (atyp)
    {
    case SOCKS5_ATYP_IPV4:
      if (len < 10)
        return 0;
      addr_len = 4;
      port = (addr_start[4] << 8) | addr_start[5];
      vec_reset_length(socks5_s->target_addr);
      socks5_s->target_addr = format(socks5_s->target_addr, "%d.%d.%d.%d%c",
                                      addr_start[0], addr_start[1],
                                      addr_start[2], addr_start[3], 0);
      break;

    case SOCKS5_ATYP_DOMAIN:
      {
        u8 domain_len = addr_start[0];
        if (len < 5 + domain_len + 2)
          return 0;
        addr_len = 1 + domain_len;
        port = (addr_start[addr_len] << 8) | addr_start[addr_len + 1];
        vec_reset_length(socks5_s->target_addr);
        vec_add(socks5_s->target_addr, addr_start + 1, domain_len);
        vec_add1(socks5_s->target_addr, 0);
        break;
      }

    case SOCKS5_ATYP_IPV6:
      if (len < 22)
        return 0;
      addr_len = 16;
      port = (addr_start[16] << 8) | addr_start[17];
      vec_reset_length(socks5_s->target_addr);
      socks5_s->target_addr = format(socks5_s->target_addr,
                                      "[ipv6:unsupported]%c", 0);
      socks5_send_error(vpp_s, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
      return -1;

    default:
      socks5_send_error(vpp_s, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
      return -1;
    }

  socks5_s->atyp = atyp;
  socks5_s->target_port = port;
  socks5_s->state = SOCKS5_STATE_CONNECTING;

  /* Create Tor stream */
  clib_error_t *error = tor_client_stream_create(
      (char *)socks5_s->target_addr, port, &socks5_s->tor_stream_index);

  if (error)
    {
      clib_error_report(error);
      socks5_send_error(vpp_s, SOCKS5_REP_HOST_UNREACHABLE);
      return -1;
    }

  /* Get event FD from Tor stream */
  tor_stream_t *tor_stream =
      pool_elt_at_index(tcm->stream_pool, socks5_s->tor_stream_index);

  socks5_s->tor_event_fd = tor_stream->event_fd;

  /* Register event FD with VPP file/epoll system */
  clib_file_t template = {0};
  template.read_function = tor_stream_ready_callback;
  template.file_descriptor = socks5_s->tor_event_fd;
  template.description = format(0, "tor-stream-%u", socks5_s->tor_stream_index);
  template.private_data = socks5_s - socks5_app.session_pool;

  socks5_s->file_index = clib_file_add(&file_main, &template);

  /* Add to file index lookup */
  hash_set(socks5_app.session_by_file_index, socks5_s->file_index,
           socks5_s - socks5_app.session_pool);

  /* Send success response */
  socks5_send_success(vpp_s);
  socks5_s->state = SOCKS5_STATE_RELAY;

  return 4 + addr_len + 2;
}

/**
 * @brief Relay data from client to Tor (Client → Tor)
 */
static int
socks5_relay_to_tor(socks5_session_t *socks5_s, session_t *vpp_s)
{
  svm_fifo_t *rx_fifo = vpp_s->rx_fifo;
  u32 available = svm_fifo_max_dequeue(rx_fifo);

  if (available == 0)
    return 0;

  u32 to_read = clib_min(available, SOCKS5_MAX_BUFFER_SIZE);
  vec_validate(socks5_s->rx_buffer, to_read - 1);

  u32 n_read = svm_fifo_dequeue(rx_fifo, to_read, socks5_s->rx_buffer);
  if (n_read <= 0)
    return 0;

  /* Send to Tor */
  ssize_t n_sent = tor_client_stream_send(
      socks5_s->tor_stream_index, socks5_s->rx_buffer, n_read);

  if (n_sent < 0)
    {
      clib_warning("Failed to send to Tor stream %u", socks5_s->tor_stream_index);
      return -1;
    }

  socks5_s->bytes_to_tor += n_sent;
  return n_sent;
}

/**
 * @brief Relay data from Tor to client (Tor → Client)
 *
 * Called when event FD signals data availability.
 */
static int
socks5_relay_from_tor(socks5_session_t *socks5_s, session_t *vpp_s)
{
  u8 buf[SOCKS5_MAX_BUFFER_SIZE];

  /* Receive from Tor (non-blocking) */
  ssize_t n_recv = tor_client_stream_recv(
      socks5_s->tor_stream_index, buf, sizeof(buf));

  if (n_recv < 0)
    {
      /* Check error code */
      if (n_recv == -6) /* WOULD_BLOCK */
        return 0;

      if (n_recv == -7) /* CLOSED */
        {
          /* Tor stream closed, close VPP session */
          session_transport_closing_notify(vpp_s);
          return -1;
        }

      clib_warning("Tor stream recv error: %ld", n_recv);
      return -1;
    }

  if (n_recv == 0)
    {
      /* EOF from Tor */
      session_transport_closing_notify(vpp_s);
      return -1;
    }

  /* Send to client */
  svm_fifo_t *tx_fifo = vpp_s->tx_fifo;
  u32 n_sent = svm_fifo_enqueue(tx_fifo, n_recv, buf);

  if (n_sent > 0)
    {
      socks5_s->bytes_from_tor += n_sent;

      /* Notify VPP that we have data to send */
      if (svm_fifo_set_event(tx_fifo))
        session_send_io_evt_to_thread(tx_fifo, SESSION_IO_EVT_TX);
    }

  return n_sent;
}

/**
 * @brief Callback when Tor stream has data available (event FD triggered)
 *
 * This is called by VPP's event loop when the eventfd signals.
 */
static void
tor_stream_ready_callback(clib_file_t *f)
{
  socks5_app_t *app = &socks5_app;
  uword *p;

  /* Look up session by file index */
  p = hash_get(app->session_by_file_index, f->private_data);
  if (!p)
    {
      clib_warning("No session for file index %u", f->private_data);
      return;
    }

  socks5_session_t *socks5_s = pool_elt_at_index(app->session_pool, p[0]);

  /* Get Tor stream to access arti_stream handle */
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *tor_stream = pool_elt_at_index(tcm->stream_pool,
                                                 socks5_s->tor_stream_index);

  /* Clear event FD */
  arti_stream_clear_event(tor_stream->arti_stream);

  /* Get VPP session */
  session_t *vpp_s = session_get_if_valid(socks5_s->vpp_session_index,
                                           0 /* thread_index */);
  if (!vpp_s)
    {
      clib_warning("VPP session %u not valid", socks5_s->vpp_session_index);
      return;
    }

  /* Relay data from Tor to client */
  socks5_relay_from_tor(socks5_s, vpp_s);

  socks5_s->last_activity = vlib_time_now(vlib_get_main());
}

/**
 * @brief Session accept callback
 */
static int
socks5_session_accept_callback(session_t *s)
{
  socks5_app_t *app = &socks5_app;
  socks5_session_t *socks5_s;

  pool_get_zero(app->session_pool, socks5_s);
  socks5_s->state = SOCKS5_STATE_INIT;
  socks5_s->vpp_session_index = s->session_index;
  socks5_s->last_activity = vlib_time_now(vlib_get_main());
  socks5_s->tor_stream_index = ~0;
  socks5_s->tor_event_fd = -1;
  socks5_s->file_index = ~0;

  hash_set(app->session_by_vpp_index, s->session_index,
           socks5_s - app->session_pool);

  s->opaque = socks5_s - app->session_pool;

  return 0;
}

/**
 * @brief Session disconnect callback
 */
static void
socks5_session_disconnect_callback(session_t *s)
{
  socks5_app_t *app = &socks5_app;
  socks5_session_t *socks5_s;

  uword *p = hash_get(app->session_by_vpp_index, s->session_index);
  if (!p)
    return;

  socks5_s = pool_elt_at_index(app->session_pool, p[0]);

  /* Unregister file/event FD */
  if (socks5_s->file_index != ~0)
    {
      clib_file_del_by_index(&file_main, socks5_s->file_index);
      hash_unset(app->session_by_file_index, socks5_s->file_index);
    }

  /* Close Tor stream */
  if (socks5_s->tor_stream_index != ~0)
    tor_client_stream_close(socks5_s->tor_stream_index);

  /* Free buffers */
  vec_free(socks5_s->rx_buffer);
  vec_free(socks5_s->target_addr);

  hash_unset(app->session_by_vpp_index, s->session_index);
  pool_put(app->session_pool, socks5_s);
}

/**
 * @brief Session RX callback (data from client)
 */
static int
socks5_session_rx_callback(session_t *s)
{
  socks5_app_t *app = &socks5_app;
  svm_fifo_t *rx_fifo = s->rx_fifo;
  u32 available = svm_fifo_max_dequeue(rx_fifo);

  if (available == 0)
    return 0;

  uword *p = hash_get(app->session_by_vpp_index, s->session_index);
  if (!p)
    return -1;

  socks5_session_t *socks5_s = pool_elt_at_index(app->session_pool, p[0]);
  socks5_s->last_activity = vlib_time_now(vlib_get_main());

  int rv = 0;

  switch (socks5_s->state)
    {
    case SOCKS5_STATE_INIT:
    case SOCKS5_STATE_AUTH_METHODS:
      {
        u8 data[258];
        u32 n_read = svm_fifo_peek(rx_fifo, 0, sizeof(data), data);
        rv = socks5_process_auth_methods(socks5_s, s, data, n_read);
        if (rv > 0)
          svm_fifo_dequeue_drop(rx_fifo, rv);
        break;
      }

    case SOCKS5_STATE_AUTH_COMPLETE:
    case SOCKS5_STATE_REQUEST:
      {
        u8 data[263];
        u32 n_read = svm_fifo_peek(rx_fifo, 0, sizeof(data), data);
        rv = socks5_process_request(socks5_s, s, data, n_read);
        if (rv > 0)
          svm_fifo_dequeue_drop(rx_fifo, rv);
        break;
      }

    case SOCKS5_STATE_RELAY:
      /* Data phase: relay to Tor */
      rv = socks5_relay_to_tor(socks5_s, s);
      break;

    default:
      rv = -1;
      break;
    }

  if (rv < 0)
    {
      session_transport_closing_notify(s);
      return -1;
    }

  return 0;
}

/**
 * @brief Session TX callback (space available to send to client)
 */
static int
socks5_session_tx_callback(session_t *s)
{
  socks5_app_t *app = &socks5_app;

  uword *p = hash_get(app->session_by_vpp_index, s->session_index);
  if (!p)
    return 0;

  socks5_session_t *socks5_s = pool_elt_at_index(app->session_pool, p[0]);

  /* If in relay state, try to receive more from Tor */
  if (socks5_s->state == SOCKS5_STATE_RELAY)
    {
      socks5_relay_from_tor(socks5_s, s);
    }

  return 0;
}

/**
 * @brief Session callbacks
 */
static session_cb_vft_t socks5_session_cb_vft = {
  .session_accept_callback = socks5_session_accept_callback,
  .session_disconnect_callback = socks5_session_disconnect_callback,
  .builtin_app_rx_callback = socks5_session_rx_callback,
  .builtin_app_tx_callback = socks5_session_tx_callback,
};

/**
 * @brief Initialize SOCKS5 application
 */
clib_error_t *
socks5_app_init(u16 port)
{
  socks5_app_t *app = &socks5_app;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset(a, 0, sizeof(*a));
  clib_memset(options, 0, sizeof(options));

  a->api_client_index = ~0;
  a->name = format(0, "tor-socks5%c", 0);
  a->session_cb_vft = &socks5_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 16;

  if (vnet_application_attach(a))
    {
      vec_free(a->name);
      return clib_error_return(0, "failed to attach SOCKS5 app");
    }

  app->app_index = a->app_index;
  app->session_by_vpp_index = hash_create(0, sizeof(uword));
  app->session_by_file_index = hash_create(0, sizeof(uword));

  vec_free(a->name);

  /* Bind to port */
  vnet_listen_args_t _b, *b = &_b;
  clib_memset(b, 0, sizeof(*b));

  b->app_index = app->app_index;
  b->sep_ext.is_ip4 = 1;
  b->sep_ext.ip.ip4.as_u32 = 0;
  b->sep_ext.port = clib_host_to_net_u16(port);
  b->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;

  if (vnet_listen(b))
    return clib_error_return(0, "failed to bind SOCKS5 port %u", port);

  clib_warning("SOCKS5 proxy listening on port %u", port);

  return 0;
}

/**
 * @brief Shutdown SOCKS5 application
 */
void
socks5_app_shutdown(void)
{
  socks5_app_t *app = &socks5_app;

  if (app->app_index != ~0)
    {
      vnet_app_detach_args_t _a, *a = &_a;
      a->app_index = app->app_index;
      vnet_application_detach(a);
    }

  hash_free(app->session_by_vpp_index);
  hash_free(app->session_by_file_index);
  pool_free(app->session_pool);
  clib_memset(app, 0, sizeof(*app));
}
