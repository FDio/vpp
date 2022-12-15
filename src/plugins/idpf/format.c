/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <idpf/idpf.h>

u8 *
format_idpf_device_name (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  idpf_device_t *id = idpf_get_device (i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, id->pci_dev_handle);

  if (id->name)
    return format (s, "%s", id->name);

  s = format (s, "idpf-%x/%x/%x/%x", addr->domain, addr->bus, addr->slot,
	      addr->function);
  return s;
}

u8 *
format_idpf_device_flags (u8 *s, va_list *args)
{
  idpf_device_t *id = va_arg (*args, idpf_device_t *);
  u8 *t = 0;

#define _(a, b, c)                                                            \
  if (id->flags & (1 << a))                                                   \
    t = format (t, "%s%s", t ? " " : "", c);
  foreach_idpf_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_idpf_checksum_cap_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  int not_first = 0;

  char *strs[32] = {
#define _(a, b, c) [a] = c,
    foreach_idpf_checksum_cap_flag
#undef _
  };

  for (int i = 0; i < 32; i++)
    {
      if ((flags & (1 << i)) == 0)
	continue;
      if (not_first)
	s = format (s, " ");
      if (strs[i])
	s = format (s, "%s", strs[i]);
      else
	s = format (s, "unknown(%u)", i);
      not_first = 1;
    }
  return s;
}

u8 *
format_idpf_device (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  idpf_device_t *id = idpf_get_device (i);
  u32 indent = format_get_indent (s);
  idpf_rxq_t *rxq = vec_elt_at_index (id->rxqs, 0);
  idpf_txq_t *txq = vec_elt_at_index (id->txqs, 0);

  s = format (s, "rx: queues %u, desc %u (min %u max %u)", id->n_rx_queues,
	      rxq->size, IDPF_QUEUE_SZ_MIN, IDPF_QUEUE_SZ_MAX);
  s = format (s, "\n%Utx: queues %u, desc %u (min %u max %u)",
	      format_white_space, indent, id->n_tx_queues, txq->size,
	      IDPF_QUEUE_SZ_MIN, IDPF_QUEUE_SZ_MAX);
  s = format (s, "\n%Uflags: %U", format_white_space, indent,
	      format_idpf_device_flags, id);
  s = format (s, "\n%Uchecksum capability flags: %U", format_white_space,
	      indent, format_idpf_checksum_cap_flags, id->csum_caps);

  s = format (s,
	      "\n%Unum-queue-pairs %d max-vectors %u max-mtu %u "
	      "rss-key-size %u rss-lut-size %u",
	      format_white_space, indent, id->num_queue_pairs, id->max_vectors,
	      id->max_mtu, id->rss_key_size, id->rss_lut_size);
  if (id->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, id->error);

  return s;
}

u8 *
format_idpf_input_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  idpf_input_trace_t *t = va_arg (*args, idpf_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);
  int i = 0;

  s = format (s, "idpf: %v (%d) qid %u next-node %U flow-id %u", hi->name,
	      t->hw_if_index, t->qid, format_vlib_next_node_name, vm,
	      node->index, t->next_index, t->flow_id);

  do
    {
      s =
	format (s, "\n%Udesc %u: status 0x%x error 0x%x ptype 0x%x len %u",
		format_white_space, indent + 2, i, t->qw1s[i] & pow2_mask (19),
		/* Fixme: correct the defination for idpf */
		(t->qw1s[i] >> IDPF_RXD_ERROR_SHIFT) & pow2_mask (8),
		(t->qw1s[i] >> IDPF_RXD_PTYPE_SHIFT) & pow2_mask (8),
		(t->qw1s[i] >> IDPF_RXD_LEN_SHIFT));
    }
  while ((t->qw1s[i++] & IDPF_RXD_STATUS_EOP) == 0 &&
	 i < IDPF_RX_MAX_DESC_IN_CHAIN);

  return s;
}
