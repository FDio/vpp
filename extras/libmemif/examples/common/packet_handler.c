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

#include <common.h>
#include <icmp_proto.h>

/* reply with the same data */
int
basic_packet_handler (memif_connection_t *c)
{
  int i;
  memif_buffer_t *dest, *src;

  /* in case of zero-copy the tx_buf_num will be zero, so the loop body won't
   * execute */
  for (i = 0; i < c->tx_buf_num; i++)
    {
      memcpy (c->tx_bufs[i].data, c->rx_bufs[i].data, c->rx_bufs[i].len);
    }

  return 0;
}

/* ICMPv4 and ARP handler */
int
icmp_packet_handler (memif_connection_t *c)
{
  int i;
  memif_buffer_t *dest, *src;

  /* if tx_buf_num > 0 we use non-zero-copy mode */
  if (c->tx_buf_num > 0)
    {
      for (i = 0; i < c->tx_buf_num; i++)
	{
	  resolve_packet (c->rx_bufs[i].data, c->rx_bufs[i].len,
			  c->tx_bufs[i].data, &c->tx_bufs[i].len, c->ip_addr,
			  c->hw_addr);
	}
    }
  else
    {
      for (i = 0; i < c->rx_buf_num; i++)
	{
	  resolve_packet_zero_copy (c->rx_bufs[i].data, &c->rx_bufs[i].len,
				    c->ip_addr, c->hw_addr);
	}
    }

  return 0;
}