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
#include <vnet/ip/ip_psh_cksum.h>

static_always_inline void
compute_ip_phc (void *p)
{
  if ((((u8 *) p)[0] & 0xf0) == 0x40)
    ip4_pseudo_header_cksum (p);
  else if ((((u8 *) p)[0] & 0xf0) == 0x60)
    ip6_pseudo_header_cksum (p);
}

void
compute_ip_phc_func (void **p, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      compute_ip_phc (p[0]);
      compute_ip_phc (p[1]);
      compute_ip_phc (p[2]);
      compute_ip_phc (p[3]);

      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      compute_ip_phc (p[0]);

      n_left_from -= 1;
      p += 1;
    }
}

typedef struct _phc_test_data
{
  const char *name;
  const char *description;
  u8 *data;
  u32 data_size;
  struct _phc_test_data *next;
} phc_test_data_t;

typedef struct
{
  int verbose;

  char *phc_name;
  u32 warmup_rounds;
  u32 rounds;
  u32 n_buffers;
  u32 buffer_size;
  phc_test_data_t *phc_test_data;
} phc_test_main_t;

phc_test_main_t phc_test_main;

#define PHC_TEST_REGISTER_DATA(x, ...)                                        \
  __VA_ARGS__ phc_test_data_t __phc_test_data_##x;                            \
  static void __clib_constructor __phc_test_data_fn_##x (void)                \
  {                                                                           \
    phc_test_main_t *ptm = &phc_test_main;                                    \
    __phc_test_data_##x.next = ptm->phc_test_data;                            \
    ptm->phc_test_data = &__phc_test_data_##x;                                \
  }                                                                           \
  __VA_ARGS__ phc_test_data_t __phc_test_data_##x

// ipv4
u8 phc_ipv4_tcp_data[50] = {
  0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40, 0x06, 0xc4, 0x85, 0xc0,
  0xa8, 0x0a, 0x02, 0xc0, 0xa8, 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34, 0x93,
  0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03, 0x00,
  0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

PHC_TEST_REGISTER_DATA (ipv4_tcp, static) = {
  .name = "ipv4-tcp",
  .description = "IPv4 TCP",
  .data = phc_ipv4_tcp_data,
  .data_size = sizeof (phc_ipv4_tcp_data),
};

// ip6
u8 phc_ipv6_udp_data[65] = {
  0x60, 0x0d, 0xf4, 0x97, 0x00, 0x40, 0x3a, 0x40, 0xfd, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xfd, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  0x01, 0x80, 0x00, 0x10, 0x84, 0xb1, 0x25, 0x00, 0x01, 0x22, 0x57, 0xf0, 0x60,
  0x00, 0x00, 0x00, 0x00, 0xcb, 0x4a, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

PHC_TEST_REGISTER_DATA (ipv6_udp, static) = {
  .name = "ipv6-udp",
  .description = "IPv6 UDP",
  .data = phc_ipv6_udp_data,
  .data_size = sizeof (phc_ipv6_udp_data),
};

static void
fill_buffers (vlib_main_t *vm, u32 *buffer_indices, u8 *data, u32 data_size,
	      u32 n_buffers, u32 buffer_size)
{
  int i, j;
  u64 seed = clib_cpu_time_now ();
  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      clib_memcpy_fast (b->data, data, data_size);
      b->current_data = 0;
      for (j = data_size; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
      b->current_length = buffer_size;
    }
}

static clib_error_t *
test_phc_perf (vlib_main_t *vm, phc_test_main_t *ptm)
{
  clib_error_t *err = 0;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  u64 t0[5], t1[5];
  phc_test_data_t *phc_test_data = ptm->phc_test_data;
  void **p = 0;
  int i, j;

  if (ptm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  rounds = ptm->rounds ? ptm->rounds : 100;
  n_buffers = ptm->n_buffers ? ptm->n_buffers : 256;
  warmup_rounds = ptm->warmup_rounds ? ptm->warmup_rounds : 100;
  buffer_size = ptm->buffer_size ? ptm->buffer_size : buffer_size;

  vec_validate_aligned (p, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vlib_cli_output (
    vm,
    "pseudo header checksum: buffer-size %u, n_buffers %u rounds %u "
    "warmup-rounds %u",
    buffer_size, n_buffers, rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  while (phc_test_data)
    {
      fill_buffers (vm, buffer_indices, phc_test_data->data,
		    phc_test_data->data_size, n_buffers, buffer_size);

      for (i = 0; i < n_buffers; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  p[i] = vlib_buffer_get_current (b);
	}

      for (i = 0; i < 5; i++)
	{
	  for (j = 0; j < warmup_rounds; j++)
	    {
	      compute_ip_phc_func (p, n_buffers);
	    }

	  t0[i] = clib_cpu_time_now ();
	  for (j = 0; j < rounds; j++)
	    compute_ip_phc_func (p, n_buffers);
	  t1[i] = clib_cpu_time_now ();
	}

      vlib_cli_output (
	vm, "===========================================================");
      vlib_cli_output (vm, " Test: %s", phc_test_data->description);
      vlib_cli_output (
	vm, "===========================================================");
      for (i = 0; i < 5; i++)
	{
	  f64 tpp1 = (f64) (t1[i] - t0[i]) / (n_buffers * rounds);
	  f64 Mpps1 = vm->clib_time.clocks_per_second * 1e-6 / tpp1;

	  vlib_cli_output (vm, "%-2u: %.03f ticks/packet, %.02f Mpps\n", i + 1,
			   tpp1, Mpps1);
	}
      phc_test_data = phc_test_data->next;
    }

done:
  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);

  vec_free (p);
  vec_free (buffer_indices);
  return err;
}

static clib_error_t *
test_phc_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  phc_test_main_t *ptm = &phc_test_main;
  clib_error_t *err = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	ptm->verbose = 1;
      else if (unformat (input, "detail"))
	ptm->verbose = 2;
      else if (unformat (input, "buffers %u", &ptm->n_buffers))
	;
      else if (unformat (input, "buffer-size %u", &ptm->buffer_size))
	;
      else if (unformat (input, "rounds %u", &ptm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &ptm->warmup_rounds))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  test_phc_perf (vm, ptm);

  return err;
}

VLIB_CLI_COMMAND (test_phc_command, static) = {
  .path = "test phc",
  .short_help = "test phc [buffers <n>] [buffer-size <size>] [rounds <n>] "
		"[warmup-rounds <n>]",
  .function = test_phc_command_fn,
};

static clib_error_t *
phc_test_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (phc_test_init);
