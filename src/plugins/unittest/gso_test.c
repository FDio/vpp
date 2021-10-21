/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/gso/gso.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/tcp/tcp_packet.h>

#define MAX_GSO_PACKET_SIZE	 (TCP_MAX_GSO_SZ - 1)
#define MIN_GSO_SEGMENT_SIZE	 128
#define MAX_GSO_SEGMENT_SIZE	 2048
#define DEFAULT_GSO_SEGMENT_SIZE 1448

typedef struct _gso_test_data
{
  const char *name;
  const char *description;
  u8 *data;
  u32 data_size;
  u32 l4_hdr_len;
  u8 is_l2;
  u8 is_ip6;
  struct _gso_test_data *next;
} gso_test_data_t;

typedef struct
{
  int verbose;

  char *gso_name;
  u32 warmup_rounds;
  u32 rounds;
  u32 n_buffers;
  u32 buffer_size;
  u32 packet_size;
  u32 gso_size;
  gso_test_data_t *gso_test_data;
} gso_test_main_t;

gso_test_main_t gso_test_main;

#define GSO_TEST_REGISTER_DATA(x, ...)                                        \
  __VA_ARGS__ gso_test_data_t __gso_test_data_##x;                            \
  static void __clib_constructor __gso_test_data_fn_##x (void)                \
  {                                                                           \
    gso_test_main_t *gtm = &gso_test_main;                                    \
    __gso_test_data_##x.next = gtm->gso_test_data;                            \
    gtm->gso_test_data = &__gso_test_data_##x;                                \
  }                                                                           \
  __VA_ARGS__ gso_test_data_t __gso_test_data_##x

// ipv4
u8 gso_ipv4_tcp_data[64] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18, 0x08,
  0x00, 0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40, 0x06, 0xc4, 0x85,
  0xc0, 0xa8, 0x0a, 0x02, 0xc0, 0xa8, 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34,
  0x93, 0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03,
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

GSO_TEST_REGISTER_DATA (gso_ipv4_tcp, static) = {
  .name = "ipv4-tcp",
  .description = "IPv4 TCP",
  .data = gso_ipv4_tcp_data,
  .data_size = sizeof (gso_ipv4_tcp_data),
  .l4_hdr_len = sizeof (tcp_header_t),
  .is_l2 = 1,
  .is_ip6 = 0,
};

// ipv6
u8 gso_ipv6_tcp_data[] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18,
  0x08, 0x00, 0x60, 0x0d, 0xf4, 0x97, 0x00, 0x40, 0x06, 0x40, 0xfd, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x10, 0x00, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34, 0x93,
  0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03,
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

GSO_TEST_REGISTER_DATA (gso_ipv6_tcp, static) = {
  .name = "ipv6-tcp",
  .description = "IPv6 TCP",
  .data = gso_ipv6_tcp_data,
  .data_size = sizeof (gso_ipv6_tcp_data),
  .l4_hdr_len = sizeof (tcp_header_t),
  .is_l2 = 1,
  .is_ip6 = 1,
};

static u32
fill_buffers (vlib_main_t *vm, u32 *buffer_indices, u8 *data, u32 data_size,
	      u32 n_buffers, u32 buffer_size, u32 packet_size, u32 gso_size,
	      u32 l4_hdr_len)
{
  u32 i;

  for (i = 0; i < n_buffers; i++)
    {
      u64 seed = clib_cpu_time_now ();
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      u32 len = 0;
      u32 remaining_data =
	(packet_size > buffer_size) ? (packet_size - buffer_size) : 0;

      clib_memcpy_fast (b->data, data, data_size);
      b->current_data = 0;

      for (u32 j = data_size; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
      b->current_length = buffer_size;

      if (remaining_data)
	{
	  vlib_buffer_t *pb = b;
	  u32 n_alloc,
	    n_bufs = ((remaining_data + buffer_size - 1) / buffer_size);
	  u32 *buffers = 0;
	  u32 fill_data_size;
	  u32 k = 0;

	  vec_validate (buffers, n_bufs - 1);
	  n_alloc = vlib_buffer_alloc (vm, buffers, n_bufs);
	  if (n_alloc < n_bufs)
	    {
	      vlib_buffer_free (vm, buffers, n_alloc);
	      vlib_cli_output (
		vm, "vlib buffer alloc failed at %u requested %u actual %u", i,
		n_bufs, n_alloc);
	      return i;
	    }

	  do
	    {
	      pb->next_buffer = buffers[k];
	      pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      pb = vlib_get_buffer (vm, buffers[k]);
	      pb->current_data = 0;
	      fill_data_size = clib_min (buffer_size, remaining_data);
	      remaining_data -= fill_data_size;
	      for (u32 l = 0; l < fill_data_size; l += 8)
		*(u64 *) (pb->data + l) = 1 + random_u64 (&seed);
	      pb->current_length = fill_data_size;
	      k++;
	      len += fill_data_size;
	    }
	  while (k < n_bufs);
	  b->flags |= VNET_BUFFER_F_GSO;
	  vnet_buffer2 (b)->gso_size = gso_size;
	  vnet_buffer2 (b)->gso_l4_hdr_sz = l4_hdr_len;
	}
      b->total_length_not_including_first_buffer = len;
      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    }
  return i;
}

static_always_inline u32
gso_segment_buffer_test (vlib_main_t *vm, u32 bi,
			 vnet_interface_per_thread_data_t *ptd, u8 is_l2,
			 u8 is_ip6)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  generic_header_offset_t gho = { 0 };
  u32 n_tx_bytes = 0;

  if (PREDICT_TRUE (b->flags & VNET_BUFFER_F_GSO))
    {
      vnet_generic_header_offset_parser (b, &gho, is_l2, !is_ip6, is_ip6);
      n_tx_bytes = gso_segment_buffer_inline (vm, ptd, b, &gho, is_l2, is_ip6);
    }

  return n_tx_bytes;
}

static clib_error_t *
test_gso_perf (vlib_main_t *vm, gso_test_main_t *gtm)
{
  clib_error_t *err = 0;
  vnet_interface_per_thread_data_t *ptd = 0;
  u32 packet_size = MAX_GSO_PACKET_SIZE;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 gso_size;
  u32 n_buffers, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  u64 t0, t1, t2[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  gso_test_data_t *gso_test_data = gtm->gso_test_data;
  int i, j, k;

  if (gtm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  if (gtm->packet_size > packet_size)
    return clib_error_return (0, "gso packet size must be <= %u", packet_size);

  if ((gtm->gso_size > MAX_GSO_SEGMENT_SIZE) ||
      (gtm->gso_size < MIN_GSO_SEGMENT_SIZE))
    return clib_error_return (
      0, "gso segment size must be in between %u >= and <= %u",
      MIN_GSO_SEGMENT_SIZE, MAX_GSO_SEGMENT_SIZE);

  rounds = gtm->rounds ? gtm->rounds : 256;
  n_buffers = gtm->n_buffers ? gtm->n_buffers : 256;
  warmup_rounds = gtm->warmup_rounds ? gtm->warmup_rounds : 256;
  buffer_size = gtm->buffer_size ? gtm->buffer_size : buffer_size;
  gso_size = gtm->gso_size;
  packet_size = gtm->packet_size ? gtm->packet_size : packet_size;

  vec_validate_aligned (ptd, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);

  vlib_cli_output (vm,
		   "GSO Segmentation: packet-size %u gso-size %u buffer-size "
		   "%u n_buffers %u rounds %u "
		   "warmup-rounds %u",
		   packet_size, gso_size, buffer_size, n_buffers, rounds,
		   warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  while (gso_test_data)
    {
      u32 n_filled = 0;
      u32 n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
      if (n_alloc != n_buffers)
	{
	  vlib_cli_output (vm, " Test: %s FAILED", gso_test_data->description);
	  err = clib_error_return (0, "buffer alloc failure");
	  vlib_buffer_free (vm, buffer_indices, n_alloc);
	  goto done;
	}
      n_filled =
	fill_buffers (vm, buffer_indices, gso_test_data->data,
		      gso_test_data->data_size, n_buffers, buffer_size,
		      packet_size, gso_size, gso_test_data->l4_hdr_len);

      u8 is_l2 = gso_test_data->is_l2;
      u8 is_ip6 = gso_test_data->is_ip6;

      for (k = 0; k < warmup_rounds; k++)
	{
	  for (j = 0; j < n_filled; j++)
	    gso_segment_buffer_test (vm, buffer_indices[j], &ptd[j], is_l2,
				     is_ip6);
	  for (j = 0; j < n_filled; j++)
	    {
	      vlib_buffer_free (vm, ptd[j].split_buffers,
				vec_len (ptd[j].split_buffers));
	      vec_free (ptd[j].split_buffers);
	    }
	}

      for (i = 0; i < 10; i++)
	{
	  for (k = 0; k < rounds; k++)
	    {
	      t0 = clib_cpu_time_now ();
	      for (j = 0; j < n_filled; j++)
		gso_segment_buffer_test (vm, buffer_indices[j], &ptd[j], is_l2,
					 is_ip6);
	      t1 = clib_cpu_time_now ();
	      t2[i] += (t1 - t0);
	      for (j = 0; j < n_filled; j++)
		{
		  vlib_buffer_free (vm, ptd[j].split_buffers,
				    vec_len (ptd[j].split_buffers));
		  vec_free (ptd[j].split_buffers);
		}
	    }
	}

      vlib_cli_output (
	vm, "===========================================================");
      vlib_cli_output (vm, " Test: %s", gso_test_data->description);
      vlib_cli_output (
	vm, "===========================================================");
      for (i = 0; i < 10; i++)
	{
	  // ticks per packet
	  f64 tpp1 = (f64) (t2[i]) / (n_filled * rounds);
	  // ticks per Byte
	  f64 tpB1 = (f64) (t2[i]) / (n_filled * rounds * packet_size);
	  // Packets per second
	  f64 Kpps1 = vm->clib_time.clocks_per_second * 1e-3 / tpp1;
	  // Throughput Giga-bits per second
	  f64 Gbps1 = vm->clib_time.clocks_per_second * 8 * 1e-9 / tpB1;

	  vlib_cli_output (
	    vm, "%-2u: %.03f ticks/packet, %.02f Kpps, %.02f Gbps\n", i + 1,
	    tpp1, Kpps1, Gbps1);
	}
      if (n_alloc)
	vlib_buffer_free (vm, buffer_indices, n_alloc);
      clib_memset (t2, 0, sizeof (t2));
      gso_test_data = gso_test_data->next;
    }

done:

  vec_free (ptd);
  vec_free (buffer_indices);
  return err;
}

static clib_error_t *
test_gso_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  gso_test_main_t *gtm = &gso_test_main;
  clib_error_t *err = 0;
  f64 end, start, total_time;

  gtm->gso_size = DEFAULT_GSO_SEGMENT_SIZE;
  gtm->warmup_rounds = 0;
  gtm->rounds = 0;
  gtm->n_buffers = 0;
  gtm->buffer_size = 0;
  gtm->packet_size = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	gtm->verbose = 1;
      else if (unformat (input, "detail"))
	gtm->verbose = 2;
      else if (unformat (input, "buffers %u", &gtm->n_buffers))
	;
      else if (unformat (input, "buffer-size %u", &gtm->buffer_size))
	;
      else if (unformat (input, "packet-size %u", &gtm->packet_size))
	;
      else if (unformat (input, "gso-size %u", &gtm->gso_size))
	;
      else if (unformat (input, "rounds %u", &gtm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &gtm->warmup_rounds))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  start = clib_cpu_time_now ();
  err = test_gso_perf (vm, gtm);
  end = clib_cpu_time_now ();

  total_time = (f64) (end - start) / vm->clib_time.clocks_per_second;
  vlib_cli_output (vm, "Total Time Test Took %.02f seconds", total_time);

  return err;
}

VLIB_CLI_COMMAND (test_gso_command, static) = {
  .path = "test gso",
  .short_help = "test gso [buffers <n>] [buffer-size <size>] [packet-size "
		"<size>] [gso-size <size>] [rounds <n>] "
		"[warmup-rounds <n>]",
  .function = test_gso_command_fn,
};

static clib_error_t *
gso_test_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (gso_test_init);
