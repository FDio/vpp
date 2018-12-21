/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel, Travelping and/or its affiliates.
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
*
*/


#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <dpi/dpi.h>


int
dpi_app_detection (vlib_main_t * vm, vlib_buffer_t * b,
                   dpi_flow_entry_t * flow, u8 proto,
                   u32 db_id, u8 is_ip4)
{
  dpi_main_t *dm = &dpi_main;
  u32 offs = 0;
  u8 *proto_hdr;
  u8 *uri;
  u8 *host;
  word len, uri_len;
  u8 *eol;
  u8 *s;
  u8 *url = NULL;
  dpi_adr_t *adr;

  if (is_ip4)
    {
      ip4_header_t *ip4 =
        (ip4_header_t *) (vlib_buffer_get_current (b));
      proto_hdr = ip4_next_header (ip4);
      len = clib_net_to_host_u16 (ip4->length) - sizeof (ip4_header_t);
    }
  else
    {
      ip6_header_t *ip6 =
        (ip6_header_t *) (vlib_buffer_get_current (b));
      proto_hdr = ip6_next_header (ip6);
      len = clib_net_to_host_u16 (ip6->payload_length);
    }

  if (proto == IP_PROTOCOL_TCP )
    {
      len -= tcp_header_bytes ((tcp_header_t *) proto_hdr);
      offs = proto_hdr - (u8 *) vlib_buffer_get_current (b) +
          tcp_header_bytes ((tcp_header_t *) proto_hdr);
    }
  else if (proto == IP_PROTOCOL_UDP)
    {
      len -= sizeof (udp_header_t);
      offs = proto_hdr - (u8 *) vlib_buffer_get_current (b) +
             sizeof (udp_header_t);
    }
  else
    return -1;

  if (len < vlib_buffer_length_in_chain (vm, b) - offs || len <= 0)
    /* no or invalid payload */
    return -1;

  uri = vlib_buffer_get_current (b) + offs;
  if (!is_http_request (&uri, &len))
    /* payload to short, abort DPI scanning for this flow */
    return -1;

  eol = memchr (uri, '\n', len);
  if (!eol)
    /* not EOL found */
    return -1;

  s = memchr (uri, ' ', eol - uri);
  if (!s)
    /* HTTP/0.9 - can find the Host Header */
    return -1;

  uri_len = s - uri;

  {
    u64 d0 = *(u64 *) (s + 1);

    if (d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '0') &&
    d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '1'))
      /* not HTTP 1.0 or 1.1 compatible */
      return -1;
  }

  host = eol + 1;
  len -= (eol - uri) + 1;

  while (len > 0)
    {
      if (is_host_header (&host, &len))
        break;
    }

  if (len <= 0)
    return -1;

  vec_add (url, "http://", sizeof ("http://"));
  vec_add (url, host, len);
  vec_add (url, uri, uri_len);

  vec_foreach (adr, dm->dpi_adrs)
  {
    if (dpi_db_lookup (adr->db_id, url, vec_len (url)) == 0)
      {
        flow->app_id = adr->app_id;
      }
  }

  vec_free (url);

  return 0;
}
