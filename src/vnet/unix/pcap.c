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

#include <vnet/unix/pcap.h>
#include <sys/fcntl.h>

/**
 * @file
 * @brief PCAP function.
 *
 * Usage:
 *
 * <code><pre>
 * \#include <vnet/unix/pcap.h>
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
  u64 actual_size = pm->current_va - pm->file_baseva;

  (void) munmap (pm->file_baseva, pm->max_file_size);
  pm->file_baseva = 0;
  pm->flags &= ~PCAP_FLAG_INIT_DONE;

  if ((pm->flags & PCAP_FLAG_WRITE_ENABLE) == 0)
    return 0;

  if (truncate (pm->file_name, actual_size) < 0)
    clib_unix_warning ("setting file size to %llu", actual_size);

  return 0;
}

clib_error_t *
pcap_init (pcap_main_t * pm)
{
  pcap_file_header_t *fh;
  u8 zero = 0;
  int fd;

  if (pm->flags & PCAP_FLAG_INIT_DONE)
    return 0;

  if (!pm->file_name)
    pm->file_name = "/tmp/vnet.pcap";

  if (pm->flags & PCAP_FLAG_THREAD_SAFE)
    clib_spinlock_init (&pm->lock);

  fd = open (pm->file_name, O_CREAT | O_TRUNC | O_RDWR, 0664);
  if (fd < 0)
    {
      return clib_error_return_unix (0, "failed to create `%s'",
				     pm->file_name);
    }

  if (pm->max_file_size == 0ULL)
    pm->max_file_size = PCAP_DEFAULT_FILE_SIZE;

  /* Round to a multiple of the page size */
  pm->max_file_size += (u64) clib_mem_get_page_size ();
  pm->max_file_size &= ~(u64) clib_mem_get_page_size ();

  /* Set file size. */
  if (lseek (fd, pm->max_file_size - 1, SEEK_SET) == (off_t) - 1)
    {
      close (fd);
      (void) unlink (pm->file_name);
      return clib_error_return_unix (0, "file size seek");
    }

  if (write (fd, &zero, 1) != 1)
    {
      close (fd);
      (void) unlink (pm->file_name);
      return clib_error_return_unix (0, "file size write");
    }

  pm->file_baseva = mmap (0, pm->max_file_size,
			  PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (pm->file_baseva == (u8 *) MAP_FAILED)
    {
      clib_error_t *error = clib_error_return_unix (0, "mmap");
      close (fd);
      (void) unlink (pm->file_name);
      return error;
    }
  (void) close (fd);

  pm->flags |= PCAP_FLAG_INIT_DONE | PCAP_FLAG_WRITE_ENABLE;
  pm->n_packets_captured = 0;
  pm->n_pcap_data_written = 0;

  /* Initialize file header */
  fh = pm->file_header = (pcap_file_header_t *) pm->file_baseva;
  pm->current_va = pm->file_baseva + sizeof (*fh);

  fh->magic = 0xa1b2c3d4;
  fh->major_version = 2;
  fh->minor_version = 4;
  fh->time_zone = 0;
  fh->max_packet_size_in_bytes = 1 << 16;
  fh->packet_type = pm->packet_type;
  return 0;
}


/**
 * @brief mmap a PCAP file, e.g. to read from another process
 *
 * @return rc - clib_error_t
 *
 */
clib_error_t *
pcap_map (pcap_main_t * pm)
{
  clib_error_t *error = 0;
  int fd;
  pcap_file_header_t *fh;
  pcap_packet_header_t *ph;
  struct stat statb;
  u64 packets_read = 0;
  u32 min_packet_bytes = ~0;
  u32 max_packet_bytes = 0;

  if (stat (pm->file_name, &statb) < 0)
    {
      error = clib_error_return_unix (0, "stat `%s'", pm->file_name);
      goto done;
    }

  fd = open (pm->file_name, O_RDONLY);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", pm->file_name);
      goto done;
    }

  if (statb.st_size < sizeof (*fh) + sizeof (*ph))
    {
      error = clib_error_return_unix (0, "`%s' is too short", pm->file_name);
      goto done;
    }

  pm->max_file_size = statb.st_size;
  pm->file_baseva = mmap (0, statb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (pm->file_baseva == (u8 *) MAP_FAILED)
    {
      error = clib_error_return_unix (0, "mmap");
      goto done;
    }

  pm->flags |= PCAP_FLAG_INIT_DONE;
  fh = pm->file_header = (pcap_file_header_t *) pm->file_baseva;
  ph = (pcap_packet_header_t *) (fh + 1);

  if (fh->magic != 0xa1b2c3d4)
    {
      error = clib_error_return (0, "bad magic `%s'", pm->file_name);
      goto done;
    }

  /* for the client's convenience, count packets; compute min/max sizes */
  while (ph < (pcap_packet_header_t *) pm->file_baseva + pm->max_file_size)
    {
      if (ph->n_packet_bytes_stored_in_file == 0)
	break;

      packets_read++;
      min_packet_bytes =
	ph->n_packet_bytes_stored_in_file <
	min_packet_bytes ? ph->n_packet_bytes_stored_in_file :
	min_packet_bytes;
      max_packet_bytes =
	ph->n_packet_bytes_stored_in_file >
	max_packet_bytes ? ph->n_packet_bytes_stored_in_file :
	max_packet_bytes;

      ph = (pcap_packet_header_t *)
	(((u8 *) (ph)) + sizeof (*ph) + ph->n_packet_bytes_stored_in_file);
    }
  pm->packets_read = packets_read;
  pm->min_packet_bytes = min_packet_bytes;
  pm->max_packet_bytes = max_packet_bytes;

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
