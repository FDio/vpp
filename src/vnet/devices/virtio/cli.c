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
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

static clib_error_t *
virtio_pci_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  virtio_pci_create_if_args_t args;
  u32 tmp;
  u64 feature_mask = (u64) ~ (0ULL);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&args, 0, sizeof (args));
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "feature-mask 0x%llx", &feature_mask))
	args.features = feature_mask;
      else if (unformat (line_input, "elog"))
	args.enable_elog = 1;
      else if (unformat (line_input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (line_input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);


  virtio_pci_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (virtio_pci_create_command, static) = {
  .path = "create interface virtio",
  .short_help = "create interface virtio <pci-address>"
                "[feature-mask <hex-mask>] [rx-queue-size <size>] [tx-queue-size <size>]",
  .function = virtio_pci_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
virtio_pci_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  virtio_main_t *vmxm = &virtio_main;
  virtio_if_t *vd;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a virtio pci interface");

  vd = pool_elt_at_index (vmxm->interfaces, hw->dev_instance);

  virtio_pci_delete_if (vm, vd);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (virtio_pci_delete_command, static) = {
  .path = "delete interface virtio",
  .short_help = "delete interface virtio"
    "{<interface> | sw_if_index <sw_idx>}",
  .function = virtio_pci_delete_command_fn,
};
/* *INDENT-ON* */

/*
static clib_error_t *
virtio_pci_test_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  virtio_pci_device_t *vd;
  vnet_main_t *vnm = vnet_get_main ();
  int enable_elog = 0, disable_elog = 0;

  / Get a line of input. /
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "elog-on"))
	enable_elog = 1;
      else if (unformat (line_input, "elog-off"))
	disable_elog = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a virtio_pci interface");

  vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  if (enable_elog)
    vd->flags |= VMXNET3_DEVICE_F_ELOG;

  if (disable_elog)
    vd->flags &= ~VMXNET3_DEVICE_F_ELOG;

  return 0;
}
*/
/* *INDENT-OFF* */
/*VLIB_CLI_COMMAND (virtio_pci_test_command, static) = {
  .path = "test virtio pci",
  .short_help = "test virtio pci <interface> | sw_if_index <sw_idx> [irq] "
    "[elog-on] [elog-off]",
  .function = virtio_pci_test_command_fn,
};*/
/* *INDENT-ON* */
/*
static void
show_virtio_pci (vlib_main_t * vm, u32 * hw_if_indices, u8 show_descr)
{
  u32 i, desc_idx;
  virtio_pci_device_t *vd;
  vnet_main_t *vnm = &vnet_main;
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  vnet_hw_interface_t *hi;
  virtio_pci_rxq_t *rxq;
  virtio_pci_rx_desc *rxd;
  virtio_pci_rx_comp *rx_comp;
  virtio_pci_txq_t *txq;
  virtio_pci_tx_desc *txd;
  virtio_pci_tx_comp *tx_comp;
  u16 qid;

  if (!hw_if_indices)
    return;

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vd = vec_elt_at_index (vmxm->devices, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %U (ifindex %d)",
		       format_vnet_hw_if_index_name, vnm, hw_if_indices[i],
		       hw_if_indices[i]);
      vlib_cli_output (vm, "  Version: %u", vd->version);
      vlib_cli_output (vm, "  PCI Address: %U", format_vlib_pci_addr,
		       &vd->pci_addr);
      vlib_cli_output (vm, "  Mac Address: %U", format_ethernet_address,
		       vd->mac_addr);
      vlib_cli_output (vm, "  hw if index: %u", vd->hw_if_index);
      vlib_cli_output (vm, "  Device instance: %u", vd->dev_instance);
      vlib_cli_output (vm, "  Number of interrupts: %u", vd->num_intrs);

      vec_foreach_index (qid, vd->rxqs)
      {
	rxq = vec_elt_at_index (vd->rxqs, qid);
	u16 rid;

	vlib_cli_output (vm, "  Queue %u (RX)", qid);
	vlib_cli_output (vm, "    RX completion next index %u",
			 rxq->rx_comp_ring.next);
	for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
	  {
	    virtio_pci_rx_ring *ring = &rxq->rx_ring[rid];

	    vlib_cli_output (vm,
			     "    ring %u size %u fill %u "
			     "consume %u produce %u", rid,
			     rxq->size, ring->fill, ring->consume,
			     ring->produce);
	    if (show_descr)
	      {
		vlib_cli_output (vm, "RX descriptors table");
		vlib_cli_output (vm, "  %5s  %18s  %10s",
				 "slot", "address", "flags");
		for (desc_idx = 0; desc_idx < rxq->size; desc_idx++)
		  {
		    rxd = &rxq->rx_desc[rid][desc_idx];
		    vlib_cli_output (vm, "  %5u  0x%016llx  0x%08x",
				     desc_idx, rxd->address, rxd->flags);
		  }
		vlib_cli_output (vm, "RX completion descriptors table");
		vlib_cli_output (vm, "  %5s  %10s  %10s  %10s  %10s",
				 "slot", "index", "rss", "len", "flags");
		for (desc_idx = 0; desc_idx < rxq->size; desc_idx++)
		  {
		    rx_comp = &rxq->rx_comp[desc_idx];
		    vlib_cli_output (vm, "  %5u  0x%08x  %10u  %10u  0x%08x",
				     desc_idx, rx_comp->index, rx_comp->rss,
				     rx_comp->len, rx_comp->flags);
		  }
	      }
	  }
      }

      vec_foreach_index (qid, vd->rxqs)
      {
	txq = vec_elt_at_index (vd->txqs, 0);
	vlib_cli_output (vm, "  Queue %u (TX)", qid);
	vlib_cli_output (vm, "    TX completion next index %u",
			 txq->tx_comp_ring.next);
	vlib_cli_output (vm, "    size %u consume %u produce %u",
			 txq->size, txq->tx_ring.consume,
			 txq->tx_ring.produce);
	if (show_descr)
	  {
	    vlib_cli_output (vm, "TX descriptors table");
	    vlib_cli_output (vm, "  %5s  %18s  %10s  %10s",
			     "slot", "address", "flags0", "flags1");
	    for (desc_idx = 0; desc_idx < txq->size; desc_idx++)
	      {
		txd = &txq->tx_desc[desc_idx];
		vlib_cli_output (vm, "  %5u  0x%016llx  0x%08x  0x%08x",
				 desc_idx, txd->address, txd->flags[0],
				 txd->flags[1]);
	      }
	    vlib_cli_output (vm, "TX completion descriptors table");
	    vlib_cli_output (vm, "  %5s  %10s  %10s",
			     "slot", "index", "flags");
	    for (desc_idx = 0; desc_idx < txq->size; desc_idx++)
	      {
		tx_comp = &txq->tx_comp[desc_idx];
		vlib_cli_output (vm, "  %5u  0x%08x  0x%08x",
				 desc_idx, tx_comp->index, tx_comp->flags);
	      }
	  }
      }
    }
}

static clib_error_t *
show_virtio_pci_fn (vlib_main_t * vm, unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  vnet_main_t *vnm = &vnet_main;
  virtio_pci_device_t *vd;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  u8 show_descr = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  if (virtio_pci_device_class.index != hi->dev_class_index)
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  vec_add1 (hw_if_indices, hw_if_index);
	}
      else if (unformat (input, "descriptors") || unformat (input, "desc"))
	show_descr = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (vd, vmxm->devices,
		    vec_add1 (hw_if_indices, vd->hw_if_index);
	);
    }

  show_virtio_pci (vm, hw_if_indices, show_descr);

done:
  vec_free (hw_if_indices);
  return error;
}
*/
/* *INDENT-OFF* */
/*VLIB_CLI_COMMAND (show_virtio_pci_command, static) = {
  .path = "show virtio pci",
  .short_help = "show virtio pci [<interface>]",
  .function = show_virtio_pci_fn,
};*/
/* *INDENT-ON* */

clib_error_t *
virtio_pci_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (virtio_pci_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
