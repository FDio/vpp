/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <ioam/lib-e2e/ioam_seqno_lib.h>

u8 *
show_ioam_seqno_cmd_fn (u8 * s, ioam_seqno_data * seqno_data, u8 enc)
{
  seqno_rx_info *rx;

  s = format (s, "SeqNo Data:\n");
  if (enc)
    {
      s = format (s, "  Current Seq. Number : %llu\n", seqno_data->seq_num);
    }
  else
    {
      rx = &seqno_data->seqno_rx;
      s = show_ioam_seqno_analyse_data_fn (s, rx);
    }

  format (s, "\n");
  return s;
}

u8 *
show_ioam_seqno_analyse_data_fn (u8 * s, seqno_rx_info * rx)
{
  s = format (s, "  Highest Seq. Number : %llu\n", rx->bitmap.highest);
  s = format (s, "     Packets received : %llu\n", rx->rx_packets);
  s = format (s, "         Lost packets : %llu\n", rx->lost_packets);
  s = format (s, "    Reordered packets : %llu\n", rx->reordered_packets);
  s = format (s, "    Duplicate packets : %llu\n", rx->dup_packets);

  format (s, "\n");
  return s;
}

void
ioam_seqno_init_data (ioam_seqno_data * data)
{
  data->seq_num = 0;
  ioam_seqno_init_rx_info (&data->seqno_rx);
  return;
}

void
ioam_seqno_init_rx_info (seqno_rx_info * data)
{
  seqno_bitmap *bitmap = &data->bitmap;
  bitmap->window_size = SEQNO_WINDOW_SIZE;
  bitmap->array_size = SEQNO_WINDOW_ARRAY_SIZE;
  bitmap->mask = 32 * SEQNO_WINDOW_ARRAY_SIZE - 1;
  bitmap->array[0] = 0x00000000;	/* pretend we haven seen sequence numbers 0 */
  bitmap->highest = 0;

  data->dup_packets = 0;
  data->lost_packets = 0;
  data->reordered_packets = 0;
  data->rx_packets = 0;
  return;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
