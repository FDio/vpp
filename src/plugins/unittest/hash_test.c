/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vnet/hash/hash.h>
#include <vnet/ethernet/ethernet.h>

#define HASH_TEST_DATA_SIZE 2048

typedef struct _hash_test_data
{
  const char *name;
  const char *description;
  u8 *data;
  u32 data_size;
  vnet_hash_fn_type_t ftype;
  struct _hash_test_data *next;
} hash_test_data_t;

typedef struct
{
  int verbose;

  char *hash_name;
  u32 warmup_rounds;
  u32 rounds;
  u32 n_buffers;

  hash_test_data_t *hash_test_data;
} hash_test_main_t;

hash_test_main_t hash_test_main;

#define HASH_TEST_REGISTER_DATA(x, ...)                                       \
  __VA_ARGS__ hash_test_data_t __hash_test_data_##x;                          \
  static void __clib_constructor __hash_test_data_fn_##x (void)               \
  {                                                                           \
    hash_test_main_t *htm = &hash_test_main;                                  \
    __hash_test_data_##x.next = htm->hash_test_data;                          \
    htm->hash_test_data = &__hash_test_data_##x;                              \
  }                                                                           \
  __VA_ARGS__ hash_test_data_t __hash_test_data_##x

// qinq
u8 eth_qinq_ipv4_tcp_data[72] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18,
  0x88, 0xa8, 0x03, 0xe8, 0x81, 0x00, 0x03, 0xe8, 0x08, 0x00, 0x45, 0x00,
  0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40, 0x06, 0xc4, 0x85, 0xc0, 0xa8,
  0x0a, 0x02, 0xc0, 0xa8, 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34, 0x93,
  0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03,
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

HASH_TEST_REGISTER_DATA (eth_qinq_ipv4_tcp, static) = {
  .name = "eth-qinq-ipv4-tcp",
  .description = "Ethernet QinQ IPv4 TCP",
  .data = eth_qinq_ipv4_tcp_data,
  .data_size = sizeof (eth_qinq_ipv4_tcp_data),
  .ftype = VNET_HASH_FN_TYPE_ETHERNET,
};

// vlan
u8 eth_vlan_ipv4_tcp_data[68] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18,
  0x81, 0x00, 0x03, 0xe8, 0x08, 0x00, 0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42,
  0x40, 0x00, 0x40, 0x06, 0xc4, 0x85, 0xc0, 0xa8, 0x0a, 0x02, 0xc0, 0xa8,
  0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34, 0x93, 0xa8, 0x1b, 0x7b, 0xef,
  0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03, 0x00, 0x00, 0x01, 0x01,
  0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

HASH_TEST_REGISTER_DATA (eth_vlan_ipv4_tcp, static) = {
  .name = "eth-vlan-ipv4-tcp",
  .description = "Ethernet Vlan IPv4 TCP",
  .data = eth_vlan_ipv4_tcp_data,
  .data_size = sizeof (eth_vlan_ipv4_tcp_data),
  .ftype = VNET_HASH_FN_TYPE_ETHERNET,
};

// ethernet
u8 eth_ipv4_tcp_data[64] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18, 0x08,
  0x00, 0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40, 0x06, 0xc4, 0x85,
  0xc0, 0xa8, 0x0a, 0x02, 0xc0, 0xa8, 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34,
  0x93, 0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03,
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

HASH_TEST_REGISTER_DATA (eth_ipv4_tcp, static) = {
  .name = "eth-ipv4-tcp",
  .description = "Ethernet IPv4 TCP",
  .data = eth_ipv4_tcp_data,
  .data_size = sizeof (eth_ipv4_tcp_data),
  .ftype = VNET_HASH_FN_TYPE_ETHERNET,
};

// udp
u8 eth_ipv4_udp_data[42] = { 0x62, 0x36, 0xbe, 0xff, 0x91, 0x20, 0x5e,
			     0x2c, 0xaf, 0x2e, 0x1e, 0x51, 0x08, 0x00,
			     0x45, 0x00, 0x05, 0xc4, 0x9d, 0xc3, 0x40,
			     0x00, 0x33, 0x11, 0x49, 0x61, 0x3e, 0xd2,
			     0x12, 0x28, 0x0a, 0x09, 0x00, 0x02, 0x14,
			     0x58, 0xc0, 0xd8, 0x05, 0xb0, 0x75, 0xbd };

HASH_TEST_REGISTER_DATA (eth_ipv4_udp, static) = {
  .name = "eth-ipv4-udp",
  .description = "Ethernet IPv4 UDP",
  .data = eth_ipv4_udp_data,
  .data_size = sizeof (eth_ipv4_udp_data),
  .ftype = VNET_HASH_FN_TYPE_ETHERNET,
};

// ipv4
u8 ipv4_tcp_data[50] = { 0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40,
			 0x06, 0xc4, 0x85, 0xc0, 0xa8, 0x0a, 0x02, 0xc0, 0xa8,
			 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34, 0x93, 0xa8,
			 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5,
			 0xc7, 0x03, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce,
			 0xaa, 0x00, 0x2f, 0xf2, 0xc3 };

HASH_TEST_REGISTER_DATA (ipv4_tcp, static) = {
  .name = "ipv4-tcp",
  .description = "IPv4 TCP",
  .data = ipv4_tcp_data,
  .data_size = sizeof (ipv4_tcp_data),
  .ftype = VNET_HASH_FN_TYPE_IP,
};

u8 ipv4_icmp_data[84] = {
  0x45, 0x00, 0x00, 0x54, 0xb7, 0xe6, 0x40, 0x00, 0x40, 0x01, 0xed, 0x6e,
  0xc0, 0xa8, 0x0a, 0x01, 0xc0, 0xa8, 0x0a, 0x02, 0x08, 0x00, 0xc7, 0x84,
  0x00, 0x16, 0x00, 0x92, 0xfd, 0xdb, 0xd9, 0x60, 0x00, 0x00, 0x00, 0x00,
  0x91, 0xc3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
  0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37

};

HASH_TEST_REGISTER_DATA (ipv4_icmp, static) = {
  .name = "ipv4-icmp",
  .description = "IPv4 ICMP",
  .data = ipv4_icmp_data,
  .data_size = sizeof (ipv4_icmp_data),
  .ftype = VNET_HASH_FN_TYPE_IP,
};

// ip6
u8 ipv6_icmp6_data[104] = {
  0x60, 0x0d, 0xf4, 0x97, 0x00, 0x40, 0x3a, 0x40, 0xfd, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xfd, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  0x01, 0x80, 0x00, 0x10, 0x84, 0xb1, 0x25, 0x00, 0x01, 0x22, 0x57, 0xf0, 0x60,
  0x00, 0x00, 0x00, 0x00, 0xcb, 0x4a, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
  0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
  0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
};

HASH_TEST_REGISTER_DATA (ipv6_icmp6, static) = {
  .name = "ipv6-icmp6",
  .description = "IPv6 ICMP6",
  .data = ipv6_icmp6_data,
  .data_size = sizeof (ipv6_icmp6_data),
  .ftype = VNET_HASH_FN_TYPE_IP,
};

void
fill_buffers (vlib_main_t *vm, u32 *buffer_indices, u8 *data, u32 data_size,
	      u32 n_buffers)
{
  int i, j;
  u64 seed = clib_cpu_time_now ();
  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      clib_memcpy_fast (b->data, data, data_size);
      b->current_data = 0;
      for (j = data_size; j < HASH_TEST_DATA_SIZE; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
      b->current_length = HASH_TEST_DATA_SIZE;
    }
}

static clib_error_t *
test_hash_perf (vlib_main_t *vm, hash_test_main_t *htm)
{
  clib_error_t *err = 0;
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  u64 t0[5], t1[5];
  vnet_hash_fn_t hf;
  hash_test_data_t *hash_test_data = htm->hash_test_data;
  void **p = 0;
  int i, j;

  rounds = htm->rounds ? htm->rounds : 100;
  n_buffers = htm->n_buffers ? htm->n_buffers : 256;
  warmup_rounds = htm->warmup_rounds ? htm->warmup_rounds : 100;

  vec_validate_aligned (p, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vlib_cli_output (vm,
		   "%s: n_buffers %u rounds %u "
		   "warmup-rounds %u",
		   htm->hash_name, n_buffers, rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  while (hash_test_data)
    {
      fill_buffers (vm, buffer_indices, hash_test_data->data,
		    hash_test_data->data_size, n_buffers);

      for (i = 0; i < n_buffers; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  p[i] = vlib_buffer_get_current (b);
	}

      hf =
	vnet_hash_function_from_name (htm->hash_name, hash_test_data->ftype);

      if (!hf)
	{
	  err = clib_error_return (0, "wrong hash name");
	  goto done;
	}

      for (i = 0; i < 5; i++)
	{
	  u32 h[n_buffers];
	  for (j = 0; j < warmup_rounds; j++)
	    {
	      hf (p, h, n_buffers);
	    }

	  t0[i] = clib_cpu_time_now ();
	  for (j = 0; j < rounds; j++)
	    hf (p, h, n_buffers);
	  t1[i] = clib_cpu_time_now ();
	}

      vlib_cli_output (
	vm, "===========================================================");
      vlib_cli_output (vm, " Test: %s", hash_test_data->description);
      vlib_cli_output (
	vm, "===========================================================");
      for (i = 0; i < 5; i++)
	{
	  f64 tpp1 = (f64) (t1[i] - t0[i]) / (n_buffers * rounds);
	  f64 Mpps1 = vm->clib_time.clocks_per_second * 1e-6 / tpp1;

	  vlib_cli_output (vm, "%-2u: %.03f ticks/packet, %.02f Mpps\n", i + 1,
			   tpp1, Mpps1);
	}
      hash_test_data = hash_test_data->next;
    }

done:
  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);

  vec_free (p);
  vec_free (buffer_indices);
  return err;
}

static clib_error_t *
test_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  hash_test_main_t *tm = &hash_test_main;
  clib_error_t *err = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "detail"))
	tm->verbose = 2;
      else if (unformat (input, "perf %s", &tm->hash_name))
	;
      else if (unformat (input, "buffers %u", &tm->n_buffers))
	;
      else if (unformat (input, "rounds %u", &tm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &tm->warmup_rounds))
	;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
	  goto error;
	}
    }

  err = test_hash_perf (vm, tm);

error:
  vec_free (tm->hash_name);

  return err;
}

VLIB_CLI_COMMAND (test_hash_command, static) = {
  .path = "test hash",
  .short_help = "test hash [perf <hash-name>] [buffers <n>] [rounds <n>] "
		"[warmup-rounds <n>]",
  .function = test_hash_command_fn,
};

static clib_error_t *
hash_test_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (hash_test_init);
