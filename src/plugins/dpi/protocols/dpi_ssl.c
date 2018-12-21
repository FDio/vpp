/*
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <dpi/dpi.h>

typedef enum {
    State_Initial = 0,
    State_Client_Hello = 1,
    State_Server_Hello = 2,
    State_Certificate = 3,
} ssl_state;

enum {
    MAJOR_TLS = 0x3,
};

enum {
    MINOR_SSL30 = 0,
    MINOR_TLS10 = 0x1,
    MINOR_TLS11 = 0x2,
    MINOR_TLS12 = 0x3,
};

typedef enum {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
} ContentType;

typedef struct {
    u8 major;
    u8 minor;
} ProtocolVersion;

typedef struct {
    u8 type;
    ProtocolVersion version;
    u16 length;
} __attribute__ ((packed)) ssl_header;

typedef enum {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
} HandshakeType;

typedef struct {
    u8 msg_type;   /* handshake type */
    u8 length[3];  /* bytes in message */
} Handshake_header;

int dpi_ssl_detect_protocol_from_cert(u8 *payload, u32 payload_len,
                                  dpi_flow_info_t *flow);

#define dpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define dpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define dpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define dpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define dpi_min(a,b)   ((a < b) ? a : b)

static void
dpi_set_detected_protocol(dpi_flow_info_t *flow,
                          u32 upper_protocol, u32 lower_protocol)
{

  if ((upper_protocol == DPI_PROTOCOL_UNKNOWN)
      && (lower_protocol != DPI_PROTOCOL_UNKNOWN))
    upper_protocol = lower_protocol;

  if (upper_protocol == lower_protocol)
    lower_protocol = DPI_PROTOCOL_UNKNOWN;

  if ((upper_protocol != DPI_PROTOCOL_UNKNOWN)
      && (lower_protocol == DPI_PROTOCOL_UNKNOWN))
    {
      if ((flow->guessed_host_protocol_id != DPI_PROTOCOL_UNKNOWN)
          && (upper_protocol != flow->guessed_host_protocol_id))
        {
            lower_protocol = upper_protocol;
            upper_protocol = flow->guessed_host_protocol_id;
        }
    }

  flow->detected_protocol[0] = upper_protocol;
  flow->detected_protocol[1] = lower_protocol;
}

static u32
dpi_ssl_refine_master_protocol(dpi_flow_info_t *flow, u32 protocol)
{

  if(flow->l4.tcp.ssl_got_server_cert == 1)
    protocol = DPI_PROTOCOL_SSL;
  else
    protocol = DPI_PROTOCOL_SSL_NO_CERT;

  return protocol;
}

static void
dpi_ssl_add_protocol(dpi_flow_info_t *flow, u32 protocol)
{
  if ((protocol != DPI_PROTOCOL_SSL)
      && (protocol != DPI_PROTOCOL_SSL_NO_CERT))
    {
      dpi_set_detected_protocol (flow, protocol,
                                  DPI_PROTOCOL_UNKNOWN);
    }
  else
    {
      protocol = dpi_ssl_refine_master_protocol (flow, protocol);
      dpi_set_detected_protocol (flow, protocol,
                                  DPI_PROTOCOL_UNKNOWN);
    }
}

int check_punycode_string(char * buffer , int len)
{
  int i = 0;

  while(i++ < len)
    {
      if( buffer[i] == 'x' &&
      buffer[i+1] == 'n' &&
      buffer[i+2] == '-' &&
      buffer[i+3] == '-' )
    // is a punycode string
    return 1;
    }
  // not a punycode string
  return 0;
}

static void
dpi_ssl_strip_cert_trail(char *buffer, int buffer_len)
{

  int i, is_puny;

  for (i = 0; i < buffer_len; i++)
    {
      if ((buffer[i] != '.') && (buffer[i] != '-') && (buffer[i] != '_')
          && (buffer[i] != '*') && (!dpi_isalpha (buffer[i]))
          && (!dpi_isdigit (buffer[i])))
        {
          buffer[i] = '\0';
          buffer_len = i;
          break;
        }
    }

  /* check for punycode encoding */
  is_puny = check_punycode_string (buffer, buffer_len);

  // not a punycode string - need more checks
  if (is_puny == 0)
    {

      if (i > 0)
        i--;

      while (i > 0)
        {
          if (!dpi_isalpha (buffer[i]))
            {
              buffer[i] = '\0';
              buffer_len = i;
              i--;
            }
          else
            break;
        }

      for (i = buffer_len; i > 0; i--)
        {
          if (buffer[i] == '.')
            break;
          else if (dpi_isdigit (buffer[i]))
            buffer[i] = '\0', buffer_len = i;
        }
    }
}

int
dpi_ssl_get_cert (u8 *payload, u32 payload_len,
                  dpi_flow_info_t *flow,
                  char *buffer, int buffer_len)
{
  u16 total_len;
  u8 server_len;
  u8 handshake_type;
  int i;

  memset (buffer, 0, buffer_len);

  /* Only check Handshake */
  if (payload[0] == handshake)
    {
      total_len = ntohs(get_u16_t(payload, 3)) + sizeof(ssl_header);
      handshake_type = payload[5];

      /* check incomplete packet */
      if (total_len > payload_len)
        total_len = payload_len;

      if (total_len >= sizeof(ssl_header)
          && (handshake_type == certificate))
        {
          u32 id_name_num = 0;
          flow->l4.tcp.ssl_got_server_cert = 1;

          /* Check payload after handshake protocol header and message header */
          for (i = 9; i < payload_len - 3; i++)
            {
              /* check if contains id-at-commonName */
              if ((payload[i] == 0x55)
                   && (payload[i + 1] == 0x04)
                   && (payload[i + 2] == 0x03))
                {
                  /* skip the issuer since it also contains common name */
                  if (payload[i] == 0x55)
                    {
                      id_name_num++;

                      if (id_name_num != 2)
                        continue;
                    }

                  /* get server name in the subject*/
                  server_len = payload[i + 3];
                  if (server_len + i + 3 < payload_len)
                    {
                      char *server_name = (char*) &payload[i + 4];
                      u8 begin = 0, len;

                      while (begin < server_len)
                        {
                          if (!dpi_isprint (server_name[begin]))
                            begin++;
                          else
                            break;
                        }

                      len = buffer_len - 1;
                      strncpy (buffer, &server_name[begin], len);
                      buffer[len] = '\0';

                      dpi_ssl_strip_cert_trail(buffer, buffer_len);
                      snprintf(flow->protos.ssl.server_cert,
                             sizeof(flow->protos.ssl.server_cert),
                             "%s", buffer);

                      /* Server Certificate */
                      return 1;
                    }
                }
            }
        }
    }

  /* Not found */
  return 0;
}

int
dpi_ssl_try_server_cert(u8 *payload, u32 payload_len, dpi_flow_info_t *flow)
{
  /* Only check SSL Handshake packets */
  if((payload_len > 9) && (payload[0] == 0x16)) {
    char cert[64];
    int rv;

    cert[0] = '\0';
    rv = dpi_ssl_get_cert (payload, payload_len, flow,
                           cert, sizeof(cert));

    if (rv > 0) {
      if ((flow->l4.tcp.ssl_got_server_cert == 1)
          && (flow->protos.ssl.server_cert[0] != '\0'))
        /* 0 means we're done processing extra packets */
        return 0;
    }

    /* Client hello, Server Hello, and certificate packets all checked */
    if (flow->ssl_cert_num_checks >= 3)
      {
        /* We're done processing extra packets */
        return 0;
      }
  }
  /* 1 means keep looking for more packets */
  return 1;
}

void
dpi_ssl_init_extra_processing(int caseNum, dpi_flow_info_t *flow)
{
  flow->check_more_pkts = 1;

  /* 0 is the case for waiting for the server certificate */
  if (caseNum == 0)
    {
      /* At most 7 packets should almost always be enough to find the server certificate if it's there */
      flow->max_more_pkts_to_check = 7;
      flow->more_pkts_func = dpi_ssl_try_server_cert;
    }
}

int
dpi_ssl_detect_protocol_from_cert(u8 *payload, u32 payload_len,
                                  dpi_flow_info_t *flow)
{
  u32 host_protocol= DPI_PROTOCOL_UNKNOWN;
  int rv;
  char cert[64];

  /* Only check SSL handshake packets */
  if ((payload_len > (sizeof(ssl_header) + sizeof(Handshake_header)))
      && (payload[0] == handshake))
    {
      if ((flow->detected_protocol[0] == DPI_PROTOCOL_UNKNOWN)
          || (flow->detected_protocol[0] == DPI_PROTOCOL_SSL))
        {
          cert[0] = '\0';
          rv = dpi_ssl_get_cert (payload, payload_len, flow,
                                 cert, sizeof(cert));

          if (rv > 0)
            {
              dpi_search_host_protocol (flow, cert, strlen (cert),
                  DPI_PROTOCOL_SSL, &host_protocol);

              if (host_protocol != DPI_PROTOCOL_UNKNOWN)
                {
                  dpi_set_detected_protocol (
                      flow,
                      host_protocol,
                      dpi_ssl_refine_master_protocol (flow, DPI_PROTOCOL_SSL));
                  return rv;
                }
            }

          if ((flow->l4.tcp.ssl_got_server_cert == 1)
                  && (flow->protos.ssl.server_cert[0] != '\0'))
            {
              dpi_ssl_add_protocol(flow, DPI_PROTOCOL_SSL);
            }
        }
    }
  return 0;
}


void
dpi_search_tcp_ssl (u8 *payload, u32 payload_len,
                    dpi_flow_info_t *flow)
{
  u32 cur_len;
  u32 cur_len2;
  u8 handshake_type;

  /* Only check SSL handshake packet */
  if ((payload_len > (sizeof(ssl_header) + sizeof(Handshake_header)))
      && (payload[0] == handshake))
    {
      handshake_type = payload[5];

      if(handshake_type == client_hello)
        {
          flow->l4.tcp.ssl_stage = State_Client_Hello;
          return;
        }
      else if(handshake_type == server_hello)
        {
          cur_len = ntohs(get_u16_t(payload, 3)) + sizeof(ssl_header);

          /* This packet only contains Server Hello message */
          if (cur_len == payload_len)
            {
              flow->l4.tcp.ssl_stage = State_Server_Hello;
              return;
            }

          /* This packet contains Server Hello, Certificate and more messages.
           * Incomplete packet processing: TBD */
          if (payload_len >= cur_len + sizeof(ssl_header)
              && payload[cur_len] == handshake
              && payload[cur_len + 1] == MAJOR_TLS)
            {
              cur_len2 = ntohs(get_u16_t(payload, cur_len + 3))
                          + sizeof(ssl_header);
              if(payload[cur_len + 5] == certificate)
                {
                  flow->l4.tcp.ssl_stage = State_Certificate;
                  /* Get SSL certificate */
                  if(dpi_ssl_detect_protocol_from_cert(&payload[cur_len],
                                                       cur_len2, flow) > 0)
                    return;
                }
            }
        }
      else if(handshake_type == certificate)
        {
          cur_len = ntohs(get_u16_t(payload, 3)) + sizeof(ssl_header);

          /* This packet contains certificate message.
           * Incomplete packet processing: TBD  */
          if (cur_len == payload_len)
            {
              flow->l4.tcp.ssl_stage = State_Certificate;
              /* Get SSL certificate */
              if(dpi_ssl_detect_protocol_from_cert(payload,
                                                   cur_len, flow) > 0)
                return;
            }
        }
    }

  return;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
