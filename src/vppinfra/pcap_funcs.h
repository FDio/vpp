/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
  h = (void *) (d);
  h->time_in_sec = time_now;
  h->time_in_usec = 1e6 * (time_now - h->time_in_sec);
  h->n_packet_bytes_stored_in_file = n_bytes_in_trace;
  h->n_bytes_in_packet = n_bytes_in_packet;
  pm->n_packets_captured++;
  return h->data;
}

#endif /* included_vppinfra_pcap_funcs_h */
