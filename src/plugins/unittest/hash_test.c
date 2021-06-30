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

typedef struct
{
  int verbose;

  /* perf */
  vnet_hash_type_t htype;
  u32 warmup_rounds;
  u32 rounds;
  u32 buffer_size;
  u32 n_buffers;

} hash_test_main_t;

hash_test_main_t hash_test_main;

// ethernet
// vlan
// q-in-q
// ipv4
// ipv6
// tcp
// udp

u8 hash_testing_data[64] = {
  0x02, 0xfe, 0x39, 0xe5, 0x09, 0x8f, 0x02, 0xfe, 0x2d, 0x18, 0x63, 0x18, 0x08,
  0x00, 0x45, 0x00, 0x05, 0xdc, 0xdb, 0x42, 0x40, 0x00, 0x40, 0x06, 0xc4, 0x85,
  0xc0, 0xa8, 0x0a, 0x02, 0xc0, 0xa8, 0x0a, 0x01, 0xd8, 0xde, 0x14, 0x51, 0x34,
  0x93, 0xa8, 0x1b, 0x7b, 0xef, 0x2e, 0x7e, 0x80, 0x10, 0x00, 0xe5, 0xc7, 0x03,
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xaa, 0x00, 0x2f, 0xf2, 0xc3
};

void
fill_buffers (vlib_main_t *vm, u32 *buffer_indices, u32 buffer_size,
	      u32 n_buffers, u8 is_l2)
{
  int i, j;
  u64 seed = clib_cpu_time_now ();
  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      if (is_l2)
	{
	  clib_memcpy_fast (b->data, hash_testing_data,
			    sizeof (hash_testing_data));
	  b->current_length = sizeof (hash_testing_data);
	}
      else
	{
	  clib_memcpy_fast (b->data, &hash_testing_data[14],
			    sizeof (hash_testing_data) -
			      sizeof (ethernet_header_t));
	  b->current_length =
	    sizeof (hash_testing_data) - sizeof (ethernet_header_t);
	}
      b->current_data = 0;
      for (j = b->current_length; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
    }
}

static clib_error_t *
test_hash_perf (vlib_main_t *vm, hash_test_main_t *htm)
{
  clib_error_t *err = 0;
  u32 n_buffers, n_ip_alloc = 0, n_ethernet_alloc = 0, warmup_rounds, rounds;
  u32 *ip_buffer_indices = 0;
  u32 *ethernet_buffer_indices = 0;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  u64 t0[5], t1[5], t2[5];
  vnet_hash_func hash_func[VNET_HASH_FN_TYPE_N];
  void ***p = 0;
  int i, j;

  if (htm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  rounds = htm->rounds ? htm->rounds : 100;
  n_buffers = htm->n_buffers ? htm->n_buffers : 256;
  buffer_size =
    htm->buffer_size ? htm->buffer_size : sizeof (hash_testing_data);
  warmup_rounds = htm->warmup_rounds ? htm->warmup_rounds : 100;

  vec_validate_aligned (p, 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (p[0], n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (p[1], n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ip_buffer_indices, n_buffers - 1,
			CLIB_CACHE_LINE_BYTES);
  n_ip_alloc = vlib_buffer_alloc (vm, ip_buffer_indices, n_buffers);
  if (n_ip_alloc != n_buffers)
    {
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vec_validate_aligned (ethernet_buffer_indices, n_buffers - 1,
			CLIB_CACHE_LINE_BYTES);
  n_ethernet_alloc =
    vlib_buffer_alloc (vm, ethernet_buffer_indices, n_buffers);
  if (n_ethernet_alloc != n_buffers)
    {
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vlib_cli_output (vm,
		   "%U: n_buffers %u buffer-size %u rounds %u "
		   "warmup-rounds %u",
		   format_vnet_hash_type, htm->htype, n_buffers, buffer_size,
		   rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  fill_buffers (vm, ip_buffer_indices, buffer_size, n_buffers, 0 /* is_l2 */);
  fill_buffers (vm, ethernet_buffer_indices, buffer_size, n_buffers,
		1 /* is_l2 */);

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *ip = vlib_get_buffer (vm, ip_buffer_indices[i]);
      p[VNET_HASH_FN_TYPE_IP][i] = vlib_buffer_get_current (ip);

      vlib_buffer_t *eth = vlib_get_buffer (vm, ethernet_buffer_indices[i]);
      p[VNET_HASH_FN_TYPE_ETHERNET][i] = vlib_buffer_get_current (eth);
    }

  hash_func[VNET_HASH_FN_TYPE_ETHERNET] =
    vnet_hash_function_from_type (htm->htype, VNET_HASH_FN_TYPE_ETHERNET);
  hash_func[VNET_HASH_FN_TYPE_IP] =
    vnet_hash_function_from_type (htm->htype, VNET_HASH_FN_TYPE_IP);

  for (i = 0; i < 5; i++)
    {
      u32 h_ethernet[n_buffers], h_ip[n_buffers];
      for (j = 0; j < warmup_rounds; j++)
	{
	  hash_func[VNET_HASH_FN_TYPE_ETHERNET](p[VNET_HASH_FN_TYPE_ETHERNET],
						h_ethernet, n_buffers);
	  hash_func[VNET_HASH_FN_TYPE_IP](p[VNET_HASH_FN_TYPE_IP], h_ip,
					  n_buffers);
	}

      t0[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	hash_func[VNET_HASH_FN_TYPE_ETHERNET](p[VNET_HASH_FN_TYPE_ETHERNET],
					      h_ethernet, n_buffers);
      t1[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	hash_func[VNET_HASH_FN_TYPE_IP](p[VNET_HASH_FN_TYPE_IP], h_ip,
					n_buffers);
      t2[i] = clib_cpu_time_now ();
    }

  for (i = 0; i < 5; i++)
    {
      f64 tpp1 = (f64) (t1[i] - t0[i]) / (n_buffers * rounds);
      f64 tpp2 = (f64) (t2[i] - t1[i]) / (n_buffers * rounds);
      f64 Mpps1 = vm->clib_time.clocks_per_second * 1e-6 / tpp1;
      f64 Mpps2 = vm->clib_time.clocks_per_second * 1e-6 / tpp2;

      vlib_cli_output (vm,
		       "%-2u: Ethernet-hash %.03f ticks/packet, %.02f Mpps\n",
		       i + 1, tpp1, Mpps1);
      vlib_cli_output (vm, "%-2u: Ip-hash %.03f ticks/packet, %.02f Mpps\n",
		       i + 1, tpp2, Mpps2);
    }

done:
  if (n_ip_alloc)
    vlib_buffer_free (vm, ip_buffer_indices, n_ip_alloc);
  if (n_ethernet_alloc)
    vlib_buffer_free (vm, ethernet_buffer_indices, n_ethernet_alloc);

  vec_free (p[0]);
  vec_free (p[1]);
  vec_free (p);
  vec_free (ip_buffer_indices);
  vec_free (ethernet_buffer_indices);
  return err;
}

static clib_error_t *
test_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  hash_test_main_t *tm = &hash_test_main;

  memset (tm, 0, sizeof (hash_test_main_t));
  tm->htype = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "detail"))
	tm->verbose = 2;
      else if (unformat (input, "perf %U", unformat_vnet_hash_type,
			 &tm->htype))
	;
      else if (unformat (input, "buffers %u", &tm->n_buffers))
	;
      else if (unformat (input, "rounds %u", &tm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &tm->warmup_rounds))
	;
      else if (unformat (input, "buffer-size %u", &tm->buffer_size))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  return test_hash_perf (vm, tm);
}

VLIB_CLI_COMMAND (test_hash_command, static) = {
  .path = "test hash",
  .short_help = "test hash [perf <hash-type>] [buffers <n>] [rounds <n>] "
		"[warmup-rounds <n>] [buffer-size <size>]",
  .function = test_hash_command_fn,
};

static clib_error_t *
hash_test_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (hash_test_init);
