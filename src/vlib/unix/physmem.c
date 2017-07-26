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
 * physmem.c: Unix physical memory
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

#include <vlib/unix/physmem.h>

static physmem_main_t physmem_main;

static void *
unix_physmem_alloc_aligned (vlib_physmem_main_t * vpm, uword n_bytes,
			    uword alignment)
{
  physmem_main_t *pm = &physmem_main;
  uword lo_offset, hi_offset;
  uword *to_free = 0;

  /* IO memory is always at least cache aligned. */
  alignment = clib_max (alignment, CLIB_CACHE_LINE_BYTES);

  while (1)
    {
      mheap_get_aligned (pm->heap, n_bytes,
			 /* align */ alignment,
			 /* align offset */ 0,
			 &lo_offset);

      /* Allocation failed? */
      if (lo_offset == ~0)
	break;

      /* Make sure allocation does not span DMA physical chunk boundary. */
      hi_offset = lo_offset + n_bytes - 1;

      if ((lo_offset >> vpm->log2_n_bytes_per_page) ==
	  (hi_offset >> vpm->log2_n_bytes_per_page))
	break;

      /* Allocation would span chunk boundary, queue it to be freed as soon as
         we find suitable chunk. */
      vec_add1 (to_free, lo_offset);
    }

  if (to_free != 0)
    {
      uword i;
      for (i = 0; i < vec_len (to_free); i++)
	mheap_put (pm->heap, to_free[i]);
      vec_free (to_free);
    }

  return lo_offset != ~0 ? pm->heap + lo_offset : 0;
}

static void
unix_physmem_free (void *x)
{
  physmem_main_t *pm = &physmem_main;

  /* Return object to region's heap. */
  mheap_put (pm->heap, x - pm->heap);
}

static void
htlb_shutdown (void)
{
  physmem_main_t *pm = &physmem_main;

  if (!pm->shmid)
    return;
  shmctl (pm->shmid, IPC_RMID, 0);
  pm->shmid = 0;
}

/* try to use huge TLB pgs if possible */
static int
htlb_init (vlib_main_t * vm)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  physmem_main_t *pm = &physmem_main;
  u64 hugepagesize, pagesize;
  u64 pfn, seek_loc;
  u64 cur, physaddr, ptbits;
  int fd, i;

  pm->shmid = shmget (11 /* key, my amp goes to 11 */ , pm->mem_size,
		      IPC_CREAT | SHM_HUGETLB | SHM_R | SHM_W);
  if (pm->shmid < 0)
    {
      clib_unix_warning ("shmget");
      return 0;
    }

  pm->mem = shmat (pm->shmid, NULL, 0 /* flags */ );
  if (pm->mem == 0)
    {
      shmctl (pm->shmid, IPC_RMID, 0);
      return 0;
    }

  memset (pm->mem, 0, pm->mem_size);

  /* $$$ get page size info from /proc/meminfo */
  hugepagesize = 2 << 20;
  pagesize = 4 << 10;
  vpm->log2_n_bytes_per_page = min_log2 (hugepagesize);
  vec_resize (vpm->page_table, pm->mem_size / hugepagesize);

  vpm->page_mask = pow2_mask (vpm->log2_n_bytes_per_page);
  vpm->virtual.start = pointer_to_uword (pm->mem);
  vpm->virtual.size = pm->mem_size;
  vpm->virtual.end = vpm->virtual.start + vpm->virtual.size;

  fd = open ("/proc/self/pagemap", O_RDONLY);

  if (fd < 0)
    {
      (void) shmdt (pm->mem);
      return 0;
    }

  pm->heap = mheap_alloc_with_flags (pm->mem, pm->mem_size,
				     /* Don't want mheap mmap/munmap with IO memory. */
				     MHEAP_FLAG_DISABLE_VM |
				     MHEAP_FLAG_THREAD_SAFE);

  cur = pointer_to_uword (pm->mem);
  i = 0;

  while (cur < pointer_to_uword (pm->mem) + pm->mem_size)
    {
      pfn = (u64) cur / pagesize;
      seek_loc = pfn * sizeof (u64);
      if (lseek (fd, seek_loc, SEEK_SET) != seek_loc)
	{
	  clib_unix_warning ("lseek to 0x%llx", seek_loc);
	  shmctl (pm->shmid, IPC_RMID, 0);
	  close (fd);
	  return 0;
	}
      if (read (fd, &ptbits, sizeof (ptbits)) != (sizeof (ptbits)))
	{
	  clib_unix_warning ("read ptbits");
	  shmctl (pm->shmid, IPC_RMID, 0);
	  close (fd);
	  return 0;
	}

      /* bits 0-54 are the physical page number */
      physaddr = (ptbits & 0x7fffffffffffffULL) * pagesize;
      if (CLIB_DEBUG > 1)
	fformat (stderr, "pm: virtual 0x%llx physical 0x%llx\n",
		 cur, physaddr);
      vpm->page_table[i++] = physaddr;

      cur += hugepagesize;
    }
  close (fd);
  atexit (htlb_shutdown);
  return 1;
}

int vlib_app_physmem_init (vlib_main_t * vm,
			   physmem_main_t * pm, int) __attribute__ ((weak));
int
vlib_app_physmem_init (vlib_main_t * vm, physmem_main_t * pm, int x)
{
  return 0;
}

clib_error_t *
unix_physmem_init (vlib_main_t * vm, int physical_memory_required)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  physmem_main_t *pm = &physmem_main;
  clib_error_t *error = 0;

  /* Avoid multiple calls. */
  if (vm->os_physmem_alloc_aligned)
    return error;

  vm->os_physmem_alloc_aligned = unix_physmem_alloc_aligned;
  vm->os_physmem_free = unix_physmem_free;
  pm->mem = MAP_FAILED;

  if (pm->mem_size == 0)
    pm->mem_size = 16 << 20;

  /* OK, Mr. App, you tell us */
  if (vlib_app_physmem_init (vm, pm, physical_memory_required))
    return 0;

  if (!pm->no_hugepages && htlb_init (vm))
    {
      fformat (stderr, "%s: use huge pages\n", __FUNCTION__);
      return 0;
    }

  pm->mem =
    mmap (0, pm->mem_size, PROT_READ | PROT_WRITE,
	  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pm->mem == MAP_FAILED)
    {
      error = clib_error_return_unix (0, "mmap");
      goto done;
    }

  pm->heap = mheap_alloc (pm->mem, pm->mem_size);

  /* Identity map with a single page. */
  vpm->log2_n_bytes_per_page = min_log2 (pm->mem_size);
  vec_add1 (vpm->page_table, pointer_to_uword (pm->mem));

  vpm->page_mask = pow2_mask (vpm->log2_n_bytes_per_page);
  vpm->virtual.start = pointer_to_uword (pm->mem);
  vpm->virtual.size = pm->mem_size;
  vpm->virtual.end = vpm->virtual.start + vpm->virtual.size;
  vpm->is_fake = 1;

  fformat (stderr, "%s: use fake dma pages\n", __FUNCTION__);

done:
  if (error)
    {
      if (pm->mem != MAP_FAILED)
	munmap (pm->mem, pm->mem_size);
    }
  return error;
}

static clib_error_t *
show_physmem (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  physmem_main_t *pm = &physmem_main;

  if (pm->heap)
    vlib_cli_output (vm, "%U", format_mheap, pm->heap, /* verbose */ 1);
  else
    vlib_cli_output (vm, "No physmem allocated.");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_physmem_command, static) = {
  .path = "show physmem",
  .short_help = "Show physical memory allocation",
  .function = show_physmem,
};
/* *INDENT-ON* */

static clib_error_t *
show_affinity (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cpu_set_t set;
  cpu_set_t *setp = &set;
  int i, rv;
  u8 *s = 0;
  int first_set_bit_in_run = -1;
  int last_set_bit_in_run = -1;
  int output_done = 0;

  rv = sched_getaffinity (0 /* pid, 0 = this proc */ ,
			  sizeof (*setp), setp);
  if (rv < 0)
    {
      vlib_cli_output (vm, "Couldn't get affinity mask: %s\n",
		       strerror (errno));
      return 0;
    }

  for (i = 0; i < 64; i++)
    {
      if (CPU_ISSET (i, setp))
	{
	  if (first_set_bit_in_run == -1)
	    {
	      first_set_bit_in_run = i;
	      last_set_bit_in_run = i;
	      if (output_done)
		s = format (s, ",");
	      s = format (s, "%d-", i);
	      output_done = 1;
	    }
	  else
	    {
	      if (i == (last_set_bit_in_run + 1))
		last_set_bit_in_run = i;
	    }
	}
      else
	{
	  if (first_set_bit_in_run != -1)
	    {
	      if (first_set_bit_in_run == (i - 1))
		{
		  _vec_len (s) -= 2 + ((first_set_bit_in_run / 10));
		}
	      s = format (s, "%d", last_set_bit_in_run);
	      first_set_bit_in_run = -1;
	      last_set_bit_in_run = -1;
	    }
	}
    }

  if (first_set_bit_in_run != -1)
    s = format (s, "%d", first_set_bit_in_run);

  vlib_cli_output (vm, "Process runs on: %v", s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_affinity_command, static) = {
  .path = "show affinity",
  .short_help = "Show process cpu affinity",
  .function = show_affinity,
};
/* *INDENT-ON* */

static clib_error_t *
set_affinity (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cpu_set_t set;
  cpu_set_t *setp = &set;
  int i, rv;
  int another_round;
  u32 first, last;

  memset (setp, 0, sizeof (*setp));

  do
    {
      another_round = 0;
      if (unformat (input, "%d-%d,", &first, &last))
	{
	  if (first > 64 || last > 64)
	    {
	    barf1:
	      vlib_cli_output (vm, "range %d-%d invalid", first, last);
	      return 0;
	    }

	  for (i = first; i <= last; i++)
	    CPU_SET (i, setp);
	  another_round = 1;
	}
      else if (unformat (input, "%d-%d", &first, &last))
	{
	  if (first > 64 || last > 64)
	    goto barf1;

	  for (i = first; i <= last; i++)
	    CPU_SET (i, setp);
	}
      else if (unformat (input, "%d,", &first))
	{
	  if (first > 64)
	    {
	    barf2:
	      vlib_cli_output (vm, "cpu %d invalid", first);
	      return 0;
	    }
	  CPU_SET (first, setp);
	  another_round = 1;
	}
      else if (unformat (input, "%d", &first))
	{
	  if (first > 64)
	    goto barf2;

	  CPU_SET (first, setp);
	}
    }
  while (another_round);

  rv = sched_setaffinity (0 /* pid, 0 = this proc */ ,
			  sizeof (*setp), setp);

  if (rv < 0)
    {
      vlib_cli_output (vm, "Couldn't get affinity mask: %s\n",
		       strerror (errno));
      return 0;
    }
  return show_affinity (vm, input, cmd);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_affinity_command, static) = {
  .path = "set affinity",
  .short_help = "Set process cpu affinity",
  .function = set_affinity,
};
/* *INDENT-ON* */

static clib_error_t *
vlib_physmem_configure (vlib_main_t * vm, unformat_input_t * input)
{
  physmem_main_t *pm = &physmem_main;
  u32 size_in_mb;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "no-huge") || unformat (input, "no-huge-pages"))
	pm->no_hugepages = 1;

      else if (unformat (input, "size-in-mb %d", &size_in_mb) ||
	       unformat (input, "size %d", &size_in_mb))
	pm->mem_size = size_in_mb << 20;
      else
	return unformat_parse_error (input);
    }

  unformat_free (input);
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (vlib_physmem_configure, "physmem");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
