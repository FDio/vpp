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
/*
 * pcap.c: libpcap packet capture format
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/fcntl.h>
#include <vppinfra/pcap.h>

/**
 * @file
 * @brief PCAP function.
 *
 * Usage:
 *
 * <code><pre>
 * \#include <vppinfra/pcap.h>
 *
 * static pcap_main_t pcap = {
 *  .file_name = "/tmp/ip4",
 *  .n_packets_to_capture = 2,
 *  .packet_type = PCAP_PACKET_TYPE_ip,
 * };
 * </pre></code>
 *
 * To add a buffer:
 *
 *  <code><pre>pcap_add_buffer (&pcap, vm, pi0, 128);</pre></code>
 *
 * File will be written after @c n_packets_to_capture or call to pcap_write (&amp;pcap).
 *
*/

/**
 * @brief Close PCAP file
 *
 * @return rc - clib_error_t
 *
 */
clib_error_t *
pcap_close (pcap_main_t * pm)
{
  close (pm->file_descriptor);
  pm->flags &= ~PCAP_MAIN_INIT_DONE;
  pm->file_descriptor = -1;
  return 0;
}

/**
 * @brief Write PCAP file
 *
 * @return rc - clib_error_t
 *
 */
clib_error_t *
pcap_write (pcap_main_t * pm)
{
  clib_error_t *error = 0;

  if (!(pm->flags & PCAP_MAIN_INIT_DONE))
    {
      pcap_file_header_t fh;
      int n;

      if (!pm->file_name)
	pm->file_name = "/tmp/vnet.pcap";

      pm->file_descriptor =
	open (pm->file_name, O_CREAT | O_TRUNC | O_WRONLY, 0664);
      if (pm->file_descriptor < 0)
	{
	  error =
	    clib_error_return_unix (0, "failed to open `%s'", pm->file_name);
	  goto done;
	}

      pm->flags |= PCAP_MAIN_INIT_DONE;
      pm->n_pcap_data_written = 0;
      clib_spinlock_init (&pm->lock);

      /* Write file header. */
      clib_memset (&fh, 0, sizeof (fh));
      fh.magic = 0xa1b2c3d4;
      fh.major_version = 2;
      fh.minor_version = 4;
      fh.time_zone = 0;
      fh.max_packet_size_in_bytes = 1 << 16;
      fh.packet_type = pm->packet_type;
      n = write (pm->file_descriptor, &fh, sizeof (fh));
      if (n != sizeof (fh))
	{
	  if (n < 0)
	    error =
	      clib_error_return_unix (0, "write file header `%s'",
				      pm->file_name);
	  else
	    error =
	      clib_error_return (0, "short write of file header `%s'",
				 pm->file_name);
	  goto done;
	}
    }

  while (vec_len (pm->pcap_data) > pm->n_pcap_data_written)
    {
      int n = vec_len (pm->pcap_data) - pm->n_pcap_data_written;

      n = write (pm->file_descriptor,
		 vec_elt_at_index (pm->pcap_data, pm->n_pcap_data_written),
		 n);

      if (n < 0 && unix_error_is_fatal (errno))
	{
	  error = clib_error_return_unix (0, "write `%s'", pm->file_name);
	  goto done;
	}
      pm->n_pcap_data_written += n;
    }

  if (pm->n_pcap_data_written >= vec_len (pm->pcap_data))
    {
      vec_reset_length (pm->pcap_data);
      pm->n_pcap_data_written = 0;
    }

  if (pm->n_packets_captured >= pm->n_packets_to_capture)
    pcap_close (pm);

done:
  if (error)
    {
      if (pm->file_descriptor >= 0)
	close (pm->file_descriptor);
    }
  return error;
}

/**
 * @brief Read PCAP file
 *
 * @return rc - clib_error_t
 *
 */
clib_error_t *
pcap_read (pcap_main_t * pm)
{
  clib_error_t *error = 0;
  int fd, need_swap, n;
  pcap_file_header_t fh;
  pcap_packet_header_t ph;

  fd = open (pm->file_name, O_RDONLY);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", pm->file_name);
      goto done;
    }

  if (read (fd, &fh, sizeof (fh)) != sizeof (fh))
    {
      error =
	clib_error_return_unix (0, "read file header `%s'", pm->file_name);
      goto done;
    }

  need_swap = 0;
  if (fh.magic == 0xd4c3b2a1)
    {
      need_swap = 1;
#define _(t,f) fh.f = clib_byte_swap_##t (fh.f);
      foreach_pcap_file_header;
#undef _
    }

  if (fh.magic != 0xa1b2c3d4)
    {
      error = clib_error_return (0, "bad magic `%s'", pm->file_name);
      goto done;
    }

  pm->min_packet_bytes = 0;
  pm->max_packet_bytes = 0;
  while ((n = read (fd, &ph, sizeof (ph))) != 0)
    {
      u8 *data;
      u64 timestamp;
      u32 timestamp_sec;
      u32 timestamp_usec;

      if (need_swap)
	{
#define _(t,f) ph.f = clib_byte_swap_##t (ph.f);
	  foreach_pcap_packet_header;
#undef _
	}

      data = vec_new (u8, ph.n_bytes_in_packet);
      if (read (fd, data, ph.n_packet_bytes_stored_in_file) !=
	  ph.n_packet_bytes_stored_in_file)
	{
	  error = clib_error_return (0, "short read `%s'", pm->file_name);
	  goto done;
	}

      if (vec_len (pm->packets_read) == 0)
	pm->min_packet_bytes = pm->max_packet_bytes = ph.n_bytes_in_packet;
      else
	{
	  pm->min_packet_bytes =
	    clib_min (pm->min_packet_bytes, ph.n_bytes_in_packet);
	  pm->max_packet_bytes =
	    clib_max (pm->max_packet_bytes, ph.n_bytes_in_packet);
	}

      timestamp_sec = ph.time_in_sec;
      timestamp_usec = ph.time_in_usec;
      timestamp = ((u64) timestamp_sec) * 1000000 + (u64) timestamp_usec;
      vec_add1 (pm->packets_read, data);
      vec_add1 (pm->timestamps, timestamp);
    }

done:
  if (fd >= 0)
    close (fd);
  return error;

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
