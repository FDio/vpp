/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vnet/vnet.h>
#include <vnet/interface_funcs.h>

#define VIRTIO_CLONE_TEST_PACKET_SIZE 9014
#define VIRTIO_CLONE_TEST_HEAD_SIZE   64
#define VIRTIO_CLONE_TEST_MAX_BUFFERS 8

static clib_error_t *
test_virtio_clone_tx (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 bis[VIRTIO_CLONE_TEST_MAX_BUFFERS];
  u32 clones[2];
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u32 n_buffers = (VIRTIO_CLONE_TEST_PACKET_SIZE + data_size - 1) / data_size;
  u32 n_alloc;
  u16 n_cloned;
  u32 offset = 0;
  u32 i;
  vlib_frame_t *f;
  u32 *to_next;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    return clib_error_return (0, "expected a Virtio interface");
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unexpected argument");

  if (n_buffers < 2 || n_buffers > VIRTIO_CLONE_TEST_MAX_BUFFERS)
    return clib_error_return (0, "unsupported buffer size %u", data_size);

  n_alloc = vlib_buffer_alloc (vm, bis, n_buffers);
  if (n_alloc != n_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, bis, n_alloc);
      return clib_error_return (0, "buffer allocation failed");
    }

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bis[i]);
      u32 j;
      u8 *data = vlib_buffer_get_current (b);

      b->current_length = clib_min (data_size, VIRTIO_CLONE_TEST_PACKET_SIZE - offset);
      for (j = 0; j < b->current_length; j++)
	data[j] = (offset + j) & 0xff;
      if (i + 1 < n_buffers)
	{
	  b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  b->next_buffer = bis[i + 1];
	}
      offset += b->current_length;
    }

  /* Locally administered Ethernet addresses and experimental EtherType. */
  {
    vlib_buffer_t *b = vlib_get_buffer (vm, bis[0]);
    u8 *data = vlib_buffer_get_current (b);
    const u8 header[14] = {
      0x02, 0xfd, 0x00, 0x00, 0x00, 0x01, 0x02, 0xfd, 0x00, 0x00, 0x00, 0x02, 0x88, 0xb5,
    };

    clib_memcpy_fast (data, header, sizeof (header));
    b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    b->total_length_not_including_first_buffer = VIRTIO_CLONE_TEST_PACKET_SIZE - b->current_length;
  }

  n_cloned = vlib_buffer_clone_255 (vm, bis[0], clones, 2, VIRTIO_CLONE_TEST_HEAD_SIZE, 0);
  if (n_cloned != 2)
    {
      vlib_buffer_free (vm, clones, n_cloned);
      return clib_error_return (0, "buffer cloning failed");
    }

  for (i = 0; i < 2; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, clones[i]);
      vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
    }

  f = vnet_get_frame_to_sw_interface (vnm, sw_if_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = clones[0];
  to_next[1] = clones[1];
  f->n_vectors = 2;
  vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
  vlib_cli_output (vm, "queued two cloned %u-byte packets", VIRTIO_CLONE_TEST_PACKET_SIZE);
  return 0;
}

VLIB_CLI_COMMAND (test_virtio_clone_tx_command, static) = {
  .path = "test virtio clone tx",
  .short_help = "test virtio clone tx <interface>",
  .function = test_virtio_clone_tx,
};
