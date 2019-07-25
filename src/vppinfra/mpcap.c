/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <sys/fcntl.h>
#include <vppinfra/mpcap.h>

/*
 * Unfortunately, the "make test" infra won't work with mapped pcap files.
 * Given enough work [mostly in .py code], one could fix that.
 */

/**
 * @file
 * @brief mapped pcap file support
 *
 * Usage:
 *
 * <code><pre>
 * \#include <vnet/unix/mpcap.h>
 *
 * static mpcap_main_t mpcap = {
 *  .file_name = "/tmp/ip4",
 *  .n_packets_to_capture = 2,
 *  .packet_type = MPCAP_PACKET_TYPE_ip,
 * };
 * </pre></code>
 *
 * To add a buffer:
 *
 *  <code><pre>mpcap_add_buffer (&mpcap, vm, pi0, 128);</pre></code>
 *
 * File will be written after @c n_packets_to_capture
 * or call to mpcap_close
 *
 */

/**
 * @brief Close a mapped pcap file
 * @param mpcap_main_t * pm
 * @return rc - clib_error_t
 *
 */
clib_error_t *
mpcap_close (mpcap_main_t * pm)
{
  u64 actual_size = pm->current_va - pm->file_baseva;

  /* Not open? Done... */
  if ((pm->flags & MPCAP_FLAG_INIT_DONE) == 0)
    return 0;

  (void) munmap (pm->file_baseva, pm->max_file_size);
  pm->file_baseva = 0;
  pm->current_va = 0;
  pm->flags &= ~MPCAP_FLAG_INIT_DONE;

  if ((pm->flags & MPCAP_FLAG_WRITE_ENABLE) == 0)
    return 0;

  if (truncate (pm->file_name, actual_size) < 0)
    clib_unix_warning ("setting file size to %llu", actual_size);

  return 0;
}

/**
 * @brief Initialize a mapped pcap file
 * @param mpcap_main_t * pm
 * @return rc - clib_error_t
 *
 */
clib_error_t *
mpcap_init (mpcap_main_t * pm)
{
  mpcap_file_header_t *fh;
  u8 zero = 0;
  int fd;

  if (pm->flags & MPCAP_FLAG_INIT_DONE)
    return 0;

  if (!pm->file_name)
    pm->file_name = "/tmp/vppinfra.mpcap";

  if (pm->flags & MPCAP_FLAG_THREAD_SAFE)
    clib_spinlock_init (&pm->lock);

  fd = open (pm->file_name, O_CREAT | O_TRUNC | O_RDWR, 0664);
  if (fd < 0)
    {
      return clib_error_return_unix (0, "failed to create `%s'",
				     pm->file_name);
    }

  if (pm->max_file_size == 0ULL)
    pm->max_file_size = MPCAP_DEFAULT_FILE_SIZE;

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

  pm->flags |= MPCAP_FLAG_INIT_DONE | MPCAP_FLAG_WRITE_ENABLE;
  pm->n_packets_captured = 0;
  pm->n_mpcap_data_written = 0;

  /* Initialize file header */
  fh = pm->file_header = (mpcap_file_header_t *) pm->file_baseva;
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
 * @brief mmap a mapped pcap file, e.g. to read from another process
 * @param pcap_main_t *pm
 * @return rc - clib_error_t
 */
clib_error_t *
mpcap_map (mpcap_main_t * pm)
{
  clib_error_t *error = 0;
  int fd = -1;
  mpcap_file_header_t *fh;
  mpcap_packet_header_t *ph;
  struct stat statb;
  u64 packets_read = 0;
  u32 min_packet_bytes = ~0;
  u32 max_packet_bytes = 0;

  fd = open (pm->file_name, O_RDONLY);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", pm->file_name);
      goto done;
    }

  if (fstat (fd, &statb) < 0)
    {
      error = clib_error_return_unix (0, "stat `%s'", pm->file_name);
      goto done;
    }

  if ((statb.st_mode & S_IFREG) == 0)
    {
      error = clib_error_return (0, "'%s' is not a regular file",
				 pm->file_name);
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

  pm->flags |= MPCAP_FLAG_INIT_DONE;
  fh = pm->file_header = (mpcap_file_header_t *) pm->file_baseva;
  ph = (mpcap_packet_header_t *) (fh + 1);

  if (fh->magic != 0xa1b2c3d4)
    {
      error = clib_error_return (0, "bad magic `%s'", pm->file_name);
      pm->flags &= ~(MPCAP_FLAG_INIT_DONE);
      (void) munmap (pm->file_baseva, pm->max_file_size);
      goto done;
    }

  /* for the client's convenience, count packets; compute min/max sizes */
  while (ph < (mpcap_packet_header_t *) pm->file_baseva + pm->max_file_size)
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

      ph = (mpcap_packet_header_t *)
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
