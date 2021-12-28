/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <dsa/dsa.h>

static clib_error_t *
dsa_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dsa_create_args_t args;
  u32 tmp;

  clib_memset (&args, 0, sizeof (dsa_create_args_t));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_dsa_addr, &args.addr))
	;
      else if (unformat (line_input, "ring-size %u", &tmp))
	args.ring_size = (u16) tmp;
      else if (unformat (line_input, "batch-size %u", &tmp))
	args.batch_size = tmp;
      else if (unformat (line_input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  tmp = dsa_create_device (vm, &args);
  vlib_cli_output (vm, "Created DSA at %d", tmp);

  vec_free (args.name);

  return args.error;
}

VLIB_CLI_COMMAND (avf_create_command, static) = {
  .path = "create dsa",
  .short_help = "create dsa <dsa-address> name <name> "
		"[ring-size <size>] [batch-size <size>]",
  .function = dsa_create_command_fn,
};

static clib_error_t *
dsa_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 dd_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &dd_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (dd_index == ~0)
    return clib_error_return (0, "please specify dsa index");

  dsa_delete_device (vm, dd_index);
  return 0;
}

VLIB_CLI_COMMAND (avf_delete_command, static) = {
  .path = "delete dsa",
  .short_help = "delete interface index <id>",
  .function = dsa_delete_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
fill_random_data (void *buffer, uword size)
{
  uword seed = random_default_seed ();

  uword remain = size;
  const uword p = clib_mem_get_page_size ();
  uword offset = 0;

  clib_random_buffer_t rb;
  clib_random_buffer_init (&rb, seed);

  while (remain > 0)
    {
      uword fill_size = clib_min (p, remain);

      clib_random_buffer_fill (&rb, fill_size);
      void *rbuf = clib_random_buffer_get_data (&rb, fill_size);
      clib_memcpy_fast (buffer + offset, rbuf, fill_size);
      clib_random_buffer_free (&rb);

      offset += fill_size;
      remain -= fill_size;
    }

  return 0;
}

static clib_error_t *
comp_and_stat (const void *src, const void *dst, const int len,
	       const int repeat, const uword elapsed)
{
  const int size = len * repeat;
  int cmp = clib_memcmp (src, dst, size);
  if (cmp)
    {
      printf ("Error, dst is not identical as src\n");
    }
  else
    {
      printf ("Good! dst is identical as src\n");
    }

  printf ("[INFO]\tMCA copy(%d) %d bytes completed, %lu ns elapsed.\n", repeat,
	  size, elapsed);
  double throughput = size * (1e6) / (1 << 20) * (1e3) / elapsed * 8;
  double iops = 1e9 * repeat / elapsed;
  double latency = 1.0 * elapsed / repeat;
  double cost = elapsed * 1.0 / repeat / len;
  printf ("Copy stats: \n");
  printf ("Copy length (B), Throughput (Mb/s), IOPS (copy/s), Latency "
	  "(ns/copy), Time per byte (ns)\n");
  printf ("%d, %9.3f, %.2f, %.2f, %8f\n", len, throughput, iops, latency,
	  cost);

  return 0;
}

static clib_error_t *
dma_copy (vlib_main_t *vm, vlib_dsa_dev_handle_t h, const void *src,
	  const void *dst, const int len, const int repeat)
{
  // enqueue copy request
  uint64_t phy_src = uword_to_pointer (src, __u64);
  uint64_t phy_dst = uword_to_pointer (dst, __u64);
  int enqueued = 0;
  int inqueue = 0;
  const int DSA_RING_SIZE = 1024;
  const int ring_size = clib_min (DSA_RING_SIZE, 4096);
  const int threshold = ring_size / 4;
  for (; enqueued != clib_min (repeat, 2 * threshold); ++enqueued)
    {
      long int offset = (long) enqueued * len;
      dsa_enqueue_copy (h, phy_src + offset, phy_dst + offset, len);
      ++inqueue;
    }

  int count = dsa_get_completed_count (h);
  ASSERT (count == 0);

  // Timer
  u64 start_time, end_time;
  start_time = unix_time_now_nsec ();

  count = 0;
  dsa_do_copies (h);
  while (count != repeat)
    {
      int n = dsa_get_completed_count (h);
      // ++log_completed[n];
      count += n;

      inqueue -= n;
      if (enqueued != repeat && inqueue < ring_size - threshold)
	{
	  const int batch = clib_min (repeat - enqueued, threshold);
	  for (int i = 0; i != batch; ++i)
	    {
	      long int offset = (long) enqueued * len;
	      dsa_enqueue_copy (h, phy_src + offset, phy_dst + offset, len);
	      ++enqueued;
	      ++inqueue;
	    }
	}
      dsa_do_copies (h);
    }

  end_time = unix_time_now_nsec ();
  u64 elapsed = end_time - start_time;

  comp_and_stat (src, dst, len, repeat, elapsed);

  printf ("\n");

  return 0;
}

static clib_error_t *
cpu_copy (const void *src, void *dst, const int len, const int repeat)
{
  u64 start_time = 0, end_time = 0;
  start_time = unix_time_now_nsec ();

  for (int i = 0; i != repeat; ++i)
    {
      uword offset = (uword) len * i;
      clib_memcpy_fast (dst + offset, src + offset, len);
    }

  end_time = unix_time_now_nsec ();
  u64 elapsed = end_time - start_time;

  comp_and_stat (src, dst, len, repeat, elapsed);

  return 0;
}

static clib_error_t *
dsa_copy_benchmark_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  int len = 0;
  int repeat = 0;
  bool dsa = false;
  u32 index;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat (input, "len %d", &len))
	;
      else if (unformat (input, "repeat %d", &repeat))
	;
      else if (unformat (input, "dsa %d", &index))
	dsa = true;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  if (len < 1)
    return clib_error_return (0, "len must be greater than 0");
  if (repeat < 1)
    return clib_error_return (0, "repeat must be greater than 0");

  printf ("[INFO] copy size: %d, repeat: %d\n", len, repeat);
  uword v = max_log2 (len * repeat);
  uword size = 1 << v;

  /*
   * Prepare two hugepage
   */
  uword log2_page_size = clib_mem_get_log2_default_hugepage_size ();
  uword page_size = 1 << log2_page_size;
  ASSERT (page_size >= (uword) len * repeat);
  void *src = clib_mem_vm_map (0, page_size, log2_page_size, "Source");
  if (src == CLIB_MEM_VM_MAP_FAILED)
    {
      return clib_error_return (0, "Error: Hugepage map failed!");
    }
  void *dst = clib_mem_vm_map (0, page_size, log2_page_size, "Destination");
  if (dst == CLIB_MEM_VM_MAP_FAILED)
    {
      clib_mem_vm_unmap (src);
      return clib_error_return (0, "Error: Hugepage map failed!");
    }

  clib_memset (src, 0, page_size);
  clib_memset (src, 0, page_size);

  // Generate random string
  fill_random_data (src, size);

  if (dsa)
    dma_copy (vm, index, src, dst, len, repeat);
  else
    cpu_copy (src, dst, len, repeat);

  clib_mem_vm_unmap (src);
  clib_mem_vm_unmap (dst);

  return 0;
}

VLIB_CLI_COMMAND (dsa_copy_benchmark_command, static) = {
  .path = "copy benchmark",
  .short_help = "copy benchmark dsa <index> len <len> repeat <repeat>",
  .function = dsa_copy_benchmark_fn,
};

clib_error_t *
avf_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (avf_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
