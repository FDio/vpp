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
 * @brief SOCKS5 protocol implementation for Tor client
 *
 * Implements RFC 1928 (SOCKS5 Protocol) with integration to VPP session layer.
 * This provides a SOCKS5 proxy that routes connections through Tor.
 */

#include <tor_client/tor_client.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

/* SOCKS5 Protocol Constants (RFC 1928) */
#define SOCKS5_VERSION 0x05

/* Authentication methods */
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_USERNAME_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

/* Commands */
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Address types */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/* Reply codes */
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* Buffer sizes */
#define SOCKS5_MAX_BUFFER_SIZE 8192
#define SOCKS5_MAX_DOMAIN_LEN 255

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
  SOCKS5_STATE_CONNECTED,
  SOCKS5_STATE_RELAY,
  SOCKS5_STATE_CLOSING,
  SOCKS5_STATE_CLOSED,
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

  /** Tor stream index (Tor network-facing) */
  u32 tor_stream_index;

  /** Receive buffer */
  u8 *rx_buffer;

  /** Transmit buffer */
  u8 *tx_buffer;

  /** Target address */
  u8 *target_addr;

  /** Target port */
  u16 target_port;

  /** Address type */
  u8 atyp;

  /** Last activity timestamp */
  f64 last_activity;

  /** Bytes transferred statistics */
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

  /** Worker contexts (per-thread) */
  socks5_session_t **sessions_per_worker;

} socks5_app_t;

static socks5_app_t socks5_app;

/**
 * @brief Send SOCKS5 error response
 */
static int
socks5_send_error(session_t *s, u8 reply_code)
{
  u8 response[10] = {
    SOCKS5_VERSION, /* Version */
    reply_code,     /* Reply code */
    0x00,          /* Reserved */
    SOCKS5_ATYP_IPV4, /* Address type (IPv4) */
    0, 0, 0, 0,    /* Bound address (0.0.0.0) */
    0, 0           /* Bound port (0) */
  };

  svm_fifo_t *tx_fifo = s->tx_fifo;
  return svm_fifo_enqueue(tx_fifo, sizeof(response), response);
}

/**
 * @brief Send SOCKS5 success response
 */
static int
socks5_send_success(session_t *s, u8 atyp, u8 *addr, u16 port)
{
  u8 response[22]; /* Max size for IPv6 */
  u8 *p = response;

  *p++ = SOCKS5_VERSION;
  *p++ = SOCKS5_REP_SUCCESS;
  *p++ = 0x00; /* Reserved */
  *p++ = atyp;

  switch (atyp)
    {
    case SOCKS5_ATYP_IPV4:
      clib_memcpy(p, addr, 4);
      p += 4;
      break;
    case SOCKS5_ATYP_IPV6:
      clib_memcpy(p, addr, 16);
      p += 16;
      break;
    case SOCKS5_ATYP_DOMAIN:
      *p++ = strlen((char *)addr);
      clib_memcpy(p, addr, strlen((char *)addr));
      p += strlen((char *)addr);
      break;
    }

  *p++ = (port >> 8) & 0xFF;
  *p++ = port & 0xFF;

  svm_fifo_t *tx_fifo = s->tx_fifo;
  return svm_fifo_enqueue(tx_fifo, p - response, response);
}

/**
 * @brief Process SOCKS5 authentication method selection
 */
static int
socks5_process_auth_methods(socks5_session_t *socks5_s, session_t *vpp_s, u8 *data, u32 len)
{
  if (len < 2)
    return -1;

  u8 version = data[0];
  u8 nmethods = data[1];

  if (version != SOCKS5_VERSION)
    {
      /* Send error: version not supported */
      u8 response[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE};
      svm_fifo_enqueue(vpp_s->tx_fifo, sizeof(response), response);
      return -1;
    }

  if (len < 2 + nmethods)
    return 0; /* Need more data */

  /* Check if no-auth method is offered */
  u8 *methods = data + 2;
  u8 use_method = SOCKS5_AUTH_NO_ACCEPTABLE;

  for (u8 i = 0; i < nmethods; i++)
    {
      if (methods[i] == SOCKS5_AUTH_NONE)
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
socks5_process_request(socks5_session_t *socks5_s, session_t *vpp_s, u8 *data, u32 len)
{
  if (len < 4)
    return 0; /* Need more data */

  u8 version = data[0];
  u8 cmd = data[1];
  /* u8 reserved = data[2]; */
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
        return 0; /* Need more data */
      addr_len = 4;
      port = (addr_start[4] << 8) | addr_start[5];

      /* Convert to string */
      vec_reset_length(socks5_s->target_addr);
      socks5_s->target_addr = format(socks5_s->target_addr, "%d.%d.%d.%d%c",
                                      addr_start[0], addr_start[1],
                                      addr_start[2], addr_start[3], 0);
      break;

    case SOCKS5_ATYP_DOMAIN:
      {
        u8 domain_len = addr_start[0];
        if (len < 5 + domain_len + 2)
          return 0; /* Need more data */

        addr_len = 1 + domain_len;
        port = (addr_start[addr_len] << 8) | addr_start[addr_len + 1];

        /* Copy domain name */
        vec_reset_length(socks5_s->target_addr);
        vec_add(socks5_s->target_addr, addr_start + 1, domain_len);
        vec_add1(socks5_s->target_addr, 0);
        break;
      }

    case SOCKS5_ATYP_IPV6:
      if (len < 22)
        return 0; /* Need more data */
      addr_len = 16;
      port = (addr_start[16] << 8) | addr_start[17];

      /* Convert to string (simplified) */
      vec_reset_length(socks5_s->target_addr);
      socks5_s->target_addr = format(socks5_s->target_addr, "[ipv6]%c", 0);
      break;

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

  /* Send success response */
  u8 bound_addr[4] = {0, 0, 0, 0};
  socks5_send_success(vpp_s, SOCKS5_ATYP_IPV4, bound_addr, 0);

  socks5_s->state = SOCKS5_STATE_RELAY;

  return 4 + addr_len + 2;
}

/**
 * @brief Relay data from client to Tor
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
    return -1;

  socks5_s->bytes_to_tor += n_sent;
  return n_sent;
}

/**
 * @brief Relay data from Tor to client
 */
static int
socks5_relay_from_tor(socks5_session_t *socks5_s, session_t *vpp_s)
{
  vec_validate(socks5_s->tx_buffer, SOCKS5_MAX_BUFFER_SIZE - 1);

  /* Receive from Tor */
  ssize_t n_recv = tor_client_stream_recv(
      socks5_s->tor_stream_index, socks5_s->tx_buffer, SOCKS5_MAX_BUFFER_SIZE);

  if (n_recv < 0)
    return -1;

  if (n_recv == 0)
    return 0; /* EOF or would block */

  /* Send to client */
  svm_fifo_t *tx_fifo = vpp_s->tx_fifo;
  u32 n_sent = svm_fifo_enqueue(tx_fifo, n_recv, socks5_s->tx_buffer);

  if (n_sent > 0)
    socks5_s->bytes_from_tor += n_sent;

  return n_sent;
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

  hash_set(app->session_by_vpp_index, s->session_index, socks5_s - app->session_pool);

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

  /* Close Tor stream */
  if (socks5_s->tor_stream_index != ~0)
    tor_client_stream_close(socks5_s->tor_stream_index);

  /* Free buffers */
  vec_free(socks5_s->rx_buffer);
  vec_free(socks5_s->tx_buffer);
  vec_free(socks5_s->target_addr);

  hash_unset(app->session_by_vpp_index, s->session_index);
  pool_put(app->session_pool, socks5_s);
}

/**
 * @brief Session RX callback
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
        u8 data[258]; /* Max: version + nmethods + 255 methods */
        u32 n_read = svm_fifo_peek(rx_fifo, 0, sizeof(data), data);
        rv = socks5_process_auth_methods(socks5_s, s, data, n_read);
        if (rv > 0)
          svm_fifo_dequeue_drop(rx_fifo, rv);
        break;
      }

    case SOCKS5_STATE_AUTH_COMPLETE:
    case SOCKS5_STATE_REQUEST:
      {
        u8 data[263]; /* Max request size */
        u32 n_read = svm_fifo_peek(rx_fifo, 0, sizeof(data), data);
        rv = socks5_process_request(socks5_s, s, data, n_read);
        if (rv > 0)
          svm_fifo_dequeue_drop(rx_fifo, rv);
        break;
      }

    case SOCKS5_STATE_RELAY:
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
 * @brief Session callbacks
 */
static session_cb_vft_t socks5_session_cb_vft = {
  .session_accept_callback = socks5_session_accept_callback,
  .session_disconnect_callback = socks5_session_disconnect_callback,
  .builtin_app_rx_callback = socks5_session_rx_callback,
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

  vec_free(a->name);

  /* Bind to port */
  vnet_listen_args_t _b, *b = &_b;
  clib_memset(b, 0, sizeof(*b));

  b->app_index = app->app_index;
  b->sep_ext.is_ip4 = 1;
  b->sep_ext.ip.ip4.as_u32 = 0; /* INADDR_ANY */
  b->sep_ext.port = clib_host_to_net_u16(port);
  b->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;

  if (vnet_listen(b))
    return clib_error_return(0, "failed to bind SOCKS5 port %u", port);

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
  pool_free(app->session_pool);
  clib_memset(app, 0, sizeof(*app));
}
