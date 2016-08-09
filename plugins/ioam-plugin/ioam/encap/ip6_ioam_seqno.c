/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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


#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include "ip6_ioam_seqno.h"
#include "ip6_ioam_e2e.h"

ioam_seqno_data_main_t ioam_seqno_main;

void ioam_seqno_init_bitmap (ioam_seqno_data *data)
{
  seqno_bitmap *bitmap = &data->seqno_rx.bitmap;
  bitmap->window_size = SEQNO_WINDOW_SIZE;
  bitmap->array_size = SEQNO_WINDOW_ARRAY_SIZE;
  bitmap->mask = 32 * SEQNO_WINDOW_ARRAY_SIZE - 1;
  bitmap->array[0] = 0x00000000;/* pretend we haven seen sequence numbers 0*/
  bitmap->highest = 0;

  data->seq_num = 0;
  return ;
}

u32
ioam_seq_flow_create (u32 ctx)
{
  ioam_seqno_data *data = NULL;

  pool_get (ioam_seqno_main.seqno_data, data);
  ioam_seqno_init_bitmap(data);
  return ((u32) ((data) - ioam_seqno_main.seqno_data));
}

void
ioam_seqno_flow_delete (u32 seqno_opaque)
{
  /* Delete case */
  if (pool_is_free_index (ioam_seqno_main.seqno_data, seqno_opaque))
    return ;

  pool_put_index(ioam_seqno_main.seqno_data, seqno_opaque);
}

/*
 * This Routine gets called from IPv6 hop-by-hop option handling.
 * Only if we are encap node, then add PPC data.
 * On a Transit(MID) node we dont do anything with E2E headers.
 * On decap node decap is handled by seperate function.
 */
int
ioam_seqno_encap_handler (vlib_buffer_t *b, ip6_header_t *ip,
                          ip6_hop_by_hop_option_t *opt)
{
  u32 opaque_index = vnet_buffer(b)->l2_classify.opaque_index;
  ioam_e2e_option_t * e2e;
  int rv = 0;

  if (is_seqno_enabled() && !IOAM_DEAP_ENABLED(opaque_index))
    {
      ioam_seqno_data *data;
      u32 seqno_opaque;
      seqno_opaque = ioam_e2ec_get_seqno_data_from_flow_ctx(opaque_index);
      if (pool_is_free_index (ioam_seqno_main.seqno_data, seqno_opaque))
        return rv;

      data = pool_elt_at_index (ioam_seqno_main.seqno_data, seqno_opaque);
      e2e = (ioam_e2e_option_t *) opt;
      e2e->e2e_data = clib_host_to_net_u32(++data->seq_num);
    }

  return (rv);
}

/*
 * This Routine gets called on POP/Decap node.
 */
int
ioam_seqno_decap_handler (vlib_buffer_t *b, ip6_header_t *ip,
                          ip6_hop_by_hop_option_t *opt)
{
  u32 opaque_index = vnet_buffer(b)->l2_classify.opaque_index;
  ioam_e2e_option_t * e2e;
  int rv = 0;

  if (is_seqno_enabled() && IOAM_DEAP_ENABLED(opaque_index))
    {
      ioam_seqno_data *data;
      u32 seqno_opaque;
      seqno_opaque = ioam_e2ec_get_seqno_data_from_flow_ctx(opaque_index);
      if (pool_is_free_index (ioam_seqno_main.seqno_data, seqno_opaque))
        return rv;

      data = pool_elt_at_index (ioam_seqno_main.seqno_data, seqno_opaque);
      e2e = (ioam_e2e_option_t *) opt;
      ioam_analyze_seqno(&data->seqno_rx, (u64) clib_net_to_host_u32(e2e->e2e_data));
    }

  return (rv);
}

u8 *
show_ioam_seqno_cmd_fn (u8 *s, u32 seqno_opaque, u8 enc)
{
  ioam_seqno_data *seqno_data;
  seqno_rx_info *rx;

  if (pool_is_free_index (ioam_seqno_main.seqno_data, seqno_opaque))
    return s;

  seqno_data = pool_elt_at_index (ioam_seqno_main.seqno_data, seqno_opaque);
  s = format(s, "SeqNo Data:\n");
  if (enc)
    {
      s = format(s, "  Current Seq. Number : %llu\n", seqno_data->seq_num);
    }
  else
    {
      rx = &seqno_data->seqno_rx;
      s = format(s, "  Highest Seq. Number : %llu\n", rx->bitmap.highest);
      s = format(s, "     Packets received : %llu\n", rx->rx_packets);
      s = format(s, "         Lost packets : %llu\n", rx->lost_packets);
      s = format(s, "    Reordered packets : %llu\n", rx->reordered_packets);
      s = format(s, "    Duplicate packets : %llu\n", rx->dup_packets);
    }

  format(s, "\n");
  return s;
}
