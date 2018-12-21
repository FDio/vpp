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

typedef enum
{
  State_Initial = 0,
  State_Client_Hello = 1,
  State_Server_Hello = 2,
  State_Certificate = 3,
} ssl_state;

enum
{
  MAJOR_TLS = 0x3,
};

enum
{
  MINOR_SSL30 = 0,
  MINOR_TLS10 = 0x1,
  MINOR_TLS11 = 0x2,
  MINOR_TLS12 = 0x3,
};

typedef enum
{
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
} ContentType;

typedef struct
{
  u8 major;
  u8 minor;
} ProtocolVersion;

typedef struct
{
  u8 type;
  ProtocolVersion version;
  u16 length;
} __attribute__ ((packed)) ssl_header;

typedef enum
{
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

typedef struct
{
  u8 msg_type;			/* handshake type */
  u8 length[3];			/* bytes in message */
} Handshake_header;

int dpi_ssl_detect_protocol_from_cert (u8 * payload, u32 payload_len,
				       dpi_flow_info_t * flow);

#define dpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define dpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define dpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define dpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define dpi_min(a,b)   ((a < b) ? a : b)

static void
dpi_set_detected_protocol (dpi_flow_info_t * flow,
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
dpi_ssl_refine_master_protocol (dpi_flow_info_t * flow, u32 protocol)
{

  if (flow->l4.tcp.ssl_got_server_cert == 1)
    protocol = DPI_PROTOCOL_SSL;
  else
    protocol = DPI_PROTOCOL_SSL_NO_CERT;

  return protocol;
}

int
dpi_ssl_detect_protocol_from_cert (u8 * payload, u32 payload_len,
				   dpi_flow_info_t * flow)
{
  u32 host_protocol = DPI_PROTOCOL_UNKNOWN;
  int rv = 0;

  /* Only check SSL handshake packets.
   * Check first segment and subsequent segments. */
  if (((payload_len > (sizeof (ssl_header) + sizeof (Handshake_header)))
       && (payload[0] == handshake)) || (flow->detect_begin))
    {
      if ((flow->detected_protocol[0] == DPI_PROTOCOL_UNKNOWN)
	  || (flow->detected_protocol[0] == DPI_PROTOCOL_SSL))
	{
	  rv = dpi_search_host_protocol (flow, (char *) payload, payload_len,
					 DPI_PROTOCOL_SSL, &host_protocol);

	  if (host_protocol != DPI_PROTOCOL_UNKNOWN)
	    {
	      dpi_set_detected_protocol (flow, host_protocol,
					 dpi_ssl_refine_master_protocol (flow,
									 DPI_PROTOCOL_SSL));
	      return rv;
	    }
	}
    }
  return 0;
}


void
dpi_search_tcp_ssl (u8 * payload, u32 payload_len, dpi_flow_info_t * flow)
{
  u32 cur_len = payload_len;
  u32 cur_len2;
  u8 handshake_type;

  /* Check first segment of SSL Certificate message */
  if ((payload_len > (sizeof (ssl_header) + sizeof (Handshake_header)))
      && (payload[0] == handshake))
    {
      handshake_type = payload[5];

      if (handshake_type == client_hello)
	{
	  flow->l4.tcp.ssl_stage = State_Client_Hello;
	  return;
	}
      else if (handshake_type == server_hello)
	{
	  cur_len = ntohs (get_u16_t (payload, 3)) + sizeof (ssl_header);

	  /* This packet only contains Server Hello message */
	  if (cur_len == payload_len)
	    {
	      flow->l4.tcp.ssl_stage = State_Server_Hello;
	      return;
	    }

	  /* This packet contains Server Hello, Certificate and more messages */
	  if (payload_len >= cur_len + sizeof (ssl_header)
	      && payload[cur_len] == handshake
	      && payload[cur_len + 1] == MAJOR_TLS)
	    {
	      cur_len2 = ntohs (get_u16_t (payload, cur_len + 3))
		+ sizeof (ssl_header);
	      if (payload[cur_len + 5] == certificate)
		{
		  flow->l4.tcp.ssl_stage = State_Certificate;
		  flow->detect_begin = 1;
		  /* Scan segments of certificate message */
		  if (dpi_ssl_detect_protocol_from_cert (&payload[cur_len],
							 cur_len2, flow) > 0)
		    return;
		}
	    }
	}
      else if (handshake_type == certificate)
	{
	  cur_len = ntohs (get_u16_t (payload, 3)) + sizeof (ssl_header);

	  /* This packet contains first segment of certificate message */
	  if (cur_len == payload_len)
	    {
	      flow->l4.tcp.ssl_stage = State_Certificate;
	      flow->detect_begin = 1;
	      /* Scan segments of certificate message */
	      if (dpi_ssl_detect_protocol_from_cert (payload, cur_len, flow) >
		  0)
		return;
	    }
	}
      else if (flow->detect_begin)
	{
	  /* Check subsequent segments of SSL Certificate message */
	  if (dpi_ssl_detect_protocol_from_cert (payload, cur_len, flow) > 0)
	    return;
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
