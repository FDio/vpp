/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef included_vppinfra_pcap_funcs_h
#define included_vppinfra_pcap_funcs_h

/** Write out data to output file. */
clib_error_t *pcap_close (pcap_main_t * pm);
clib_error_t *pcap_write (pcap_main_t * pm);

/** Read data from file. */
clib_error_t *pcap_read (pcap_main_t * pm);

/** Close the file created by pcap_write function. */
clib_error_t *pcap_close (pcap_main_t * pm);

/**
 * @brief Add packet
 *
 * @param *pm - pcap_main_t
 * @param time_now - f64
 * @param n_bytes_in_trace - u32
 * @param n_bytes_in_packet - u32
 *
 * @return Packet Data
 *
 */
static inline void *
pcap_add_packet (pcap_main_t * pm,
		 f64 time_now, u32 n_bytes_in_trace, u32 n_bytes_in_packet)
{
  pcap_packet_header_t *h;
  u8 *d;

  vec_add2 (pm->pcap_data, d, sizeof (h[0]) + n_bytes_in_trace);
  h = (pcap_packet_header_t *) (d);
  h->time_in_sec = time_now;
  h->time_in_usec = 1e6 * (time_now - h->time_in_sec);
  h->n_packet_bytes_stored_in_file = n_bytes_in_trace;
  h->n_bytes_in_packet = n_bytes_in_packet;
  pm->n_packets_captured++;
  return h->data;
}

#endif /* included_vppinfra_pcap_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
