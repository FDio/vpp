/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <memif/memif.h>

static clib_error_t *
memif_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int r;
  u32 ring_size = MEMIF_DEFAULT_RING_SIZE;
  memif_create_if_args_t args = { 0 };
  args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "key 0x%" PRIx64, &args.key))
	;
      else if (unformat (line_input, "socket %s", &args.socket_filename))
	;
      else if (unformat (line_input, "ring-size %u", &ring_size))
	;
      else if (unformat (line_input, "buffer-size %u", &args.buffer_size))
	;
      else if (unformat (line_input, "master"))
	args.is_master = 1;
      else if (unformat (line_input, "slave"))
	args.is_master = 0;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (!is_pow2 (ring_size))
    return clib_error_return (0, "ring size must be power of 2");

  args.log2_ring_size = min_log2 (ring_size);

  r = memif_create_if (vm, &args);

  if (r <= VNET_API_ERROR_SYSCALL_ERROR_1
      && r >= VNET_API_ERROR_SYSCALL_ERROR_10)
    return clib_error_return (0, "%s (errno %d)", strerror (errno), errno);

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return (0, "Invalid interface name");

  if (r == VNET_API_ERROR_SUBIF_ALREADY_EXISTS)
    return clib_error_return (0, "Interface already exists");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_create_command, static) = {
  .path = "create memif",
  .short_help = "create memif [key <key>] [socket <path>] "
                "[ring-size <size>] [buffer-size <size>] [hw-addr <mac-address>] "
		"<master|slave>",
  .function = memif_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
memif_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 key = 0;
  u8 key_defined = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "key 0x%" PRIx64, &key))
	key_defined = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (!key_defined)
    return clib_error_return (0, "missing key");

  memif_delete_if (vm, key);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_delete_command, static) = {
  .path = "delete memif",
  .short_help = "delete memif key <key-value>",
  .function = memif_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
memif_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  vnet_main_t *vnm = vnet_get_main ();
  int i;

  /* *INDENT-OFF* */
  pool_foreach (mif, mm->interfaces,
    ({
       vlib_cli_output (vm, "interface %U", format_vnet_sw_if_index_name,
			vnm, mif->sw_if_index);
       vlib_cli_output (vm, "  key 0x%" PRIx64 " file %s", mif->key,
			mif->socket_filename);
       vlib_cli_output (vm, "  listener %d conn-fd %d int-fd %d", mif->listener_index,
			mif->connection.fd, mif->interrupt_line.fd);
       vlib_cli_output (vm, "  ring-size %u num-c2s-rings %u num-s2c-rings %u buffer_size %u",
			(1 << mif->log2_ring_size),
			mif->num_s2m_rings,
			mif->num_m2s_rings,
			mif->buffer_size);
       for (i=0; i < mif->num_s2m_rings; i++)
         {
	   memif_ring_t * ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
	   if (ring)
	     {
	       vlib_cli_output (vm, "  slave-to-master ring %u:", i);
	       vlib_cli_output (vm, "    head %u tail %u", ring->head, ring->tail);
	     }
	 }
       for (i=0; i < mif->num_m2s_rings; i++)
         {
	   memif_ring_t * ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
	   if (ring)
	     {
	       vlib_cli_output (vm, "  master-to-slave ring %u:", i);
	       vlib_cli_output (vm, "    head %u tail %u", ring->head, ring->tail);
	     }
	 }
    }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_show_command, static) = {
  .path = "show memif",
  .short_help = "show memif",
  .function = memif_show_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
memif_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (memif_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
