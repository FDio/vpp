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

#include <avf/avf.h>

#define AVF_MBOX_LEN 64
#define AVF_MBOX_BUF_SZ 512

#define AVF_ARQBAH          0x00006000
#define AVF_ATQH            0x00006400
#define AVF_ATQLEN          0x00006800
#define AVF_ARQBAL          0x00006C00
#define AVF_ARQT            0x00007000
#define AVF_ARQH            0x00007400
#define AVF_ATQBAH          0x00007800
#define AVF_ATQBAL          0x00007C00
#define AVF_ARQLEN          0x00008000
#define AVF_ATQT            0x00008400
#define AVFGEN_RSTAT        0x00008800

#define AVF_AQ_FLAG_DD  (1 << 0)
#define AVF_AQ_FLAG_CMP (1 << 1)
#define AVF_AQ_FLAG_ERR (1 << 2)
#define AVF_AQ_FLAG_VFE (1 << 3)
#define AVF_AQ_FLAG_LB  (1 << 9)
#define AVF_AQ_FLAG_RD  (1 << 10)
#define AVF_AQ_FLAG_VFC (1 << 11)
#define AVF_AQ_FLAG_BUF (1 << 12)
#define AVF_AQ_FLAG_SI  (1 << 13)
#define AVF_AQ_FLAG_EI  (1 << 14)
#define AVF_AQ_FLAG_FE  (1 << 15)

avf_main_t avf_main;

#define avf_log_debug(fmt, ...) fformat(stderr, "%s: " fmt "\n", __func__, __VA_ARGS__)

static inline u32
avf_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline u32
avf_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = avf_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
avf_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

void
avf_create_if (avf_create_if_args_t * args)
{
}

void
avf_delete_if (avf_device_t * ad)
{
}

void
avf_send_to_pf (vlib_main_t * vm, avf_device_t * ad, virtchnl_ops_t op,
		void *data, int len)
{
  avf_main_t *am = &avf_main;
  avf_aq_desc_t *d;
  u64 pa;

  d = &ad->atq[ad->atq_next_slot];
  memset (d, 0, sizeof (avf_aq_desc_t));
  d->opcode = 0x801;
  d->v_opcode = op;
  d->flags = AVF_AQ_FLAG_SI | AVF_AQ_FLAG_BUF | AVF_AQ_FLAG_RD;
  d->datalen = len;
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					 ad->atq_bufs);
  d->addr_hi = (u32) (pa >> 32);
  d->addr_lo = (u32) pa;
  clib_memcpy (ad->atq_bufs, data, len);
  CLIB_MEMORY_BARRIER ();
  avf_log_debug ("slot %u opcode %x v_opcode %x",
		 ad->atq_next_slot, d->opcode, d->v_opcode);
  avf_log_debug ("%U", format_hexdump, data, len);
  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_MBOX_LEN;
  avf_set_u32 (ad->bar0, AVF_ATQT, ad->atq_next_slot);
}

clib_error_t *
avf_device_init (vlib_main_t * vm, avf_device_t * ad)
{
  avf_main_t *am = &avf_main;
  avf_aq_desc_t *d;
  u64 pa;
  int i;
  vlib_pci_addr_t *addr = vlib_pci_get_addr (ad->pci_dev_handle);
  clib_warning ("init %U", format_vlib_pci_addr, addr);

  /* VF MailBox Receive */
  memset (ad->arq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa =
    vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->arq_bufs);
  fformat (stderr, "\narq_bufs %llx\n", pa);
  for (i = 0; i < AVF_MBOX_LEN; i++)
    {
      d = &ad->arq[i];
      d->flags = AVF_AQ_FLAG_SI | AVF_AQ_FLAG_BUF;
      d->datalen = AVF_MBOX_BUF_SZ;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      pa += AVF_MBOX_BUF_SZ;
    }

  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->arq);
  fformat (stderr, "\narq %llx\n", pa);
  avf_set_u32 (ad->bar0, AVF_ARQT, 8);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ARQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ARQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ARQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  /* VF MailBox Transmit */
  memset (ad->atq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->atq);
  fformat (stderr, "\natq %llx\n", pa);
  avf_set_u32 (ad->bar0, AVF_ATQT, 0);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ATQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ATQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ATQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  u32 rl = avf_get_u32_bits (ad->bar0, AVF_ARQLEN, 31, 0);
  u32 tl = avf_get_u32_bits (ad->bar0, AVF_ATQLEN, 31, 0);
  clib_warning ("%x %x %x %x", rl, tl,
		avf_get_u32_bits (ad->bar0, AVF_ATQBAH, 31, 0),
		avf_get_u32_bits (ad->bar0, AVF_ATQBAL, 31, 0));

  u64 ver = (1ULL << 32) | 1;
//  avf_send_to_pf (vm, ad, VIRTCHNL_OP_VERSION, &ver, sizeof (ver));

  u32 bitmap = 0x00020020;
  avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
		  sizeof (bitmap));

  avf_send_to_pf (vm, ad, VIRTCHNL_OP_VERSION, &ver, sizeof (ver));
  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return 0;
}

typedef enum
{
  VIRTCHNL_EVENT_UNKNOWN = 0,
  VIRTCHNL_EVENT_LINK_CHANGE,
  VIRTCHNL_EVENT_RESET_IMPENDING,
  VIRTCHNL_EVENT_PF_DRIVER_CLOSE,
} virtchnl_event_codes_t;

#define VIRTCHNL_LINK_SPEED_100MB_SHIFT 0x1
#define VIRTCHNL_LINK_SPEED_1000MB_SHIFT 0x2
#define VIRTCHNL_LINK_SPEED_10GB_SHIFT 0x3
#define VIRTCHNL_LINK_SPEED_40GB_SHIFT 0x4
#define VIRTCHNL_LINK_SPEED_20GB_SHIFT 0x5
#define VIRTCHNL_LINK_SPEED_25GB_SHIFT 0x6

#define BIT(x) (1 << x)
typedef enum
{
  VIRTCHNL_LINK_SPEED_UNKNOWN = 0,
  VIRTCHNL_LINK_SPEED_100MB = BIT (VIRTCHNL_LINK_SPEED_100MB_SHIFT),
  VIRTCHNL_LINK_SPEED_1GB = BIT (VIRTCHNL_LINK_SPEED_1000MB_SHIFT),
  VIRTCHNL_LINK_SPEED_10GB = BIT (VIRTCHNL_LINK_SPEED_10GB_SHIFT),
  VIRTCHNL_LINK_SPEED_40GB = BIT (VIRTCHNL_LINK_SPEED_40GB_SHIFT),
  VIRTCHNL_LINK_SPEED_20GB = BIT (VIRTCHNL_LINK_SPEED_20GB_SHIFT),
  VIRTCHNL_LINK_SPEED_25GB = BIT (VIRTCHNL_LINK_SPEED_25GB_SHIFT),
} virtchnl_link_speed_t;

typedef struct
{
  virtchnl_event_codes_t event;
  union
  {
    struct
    {
      virtchnl_link_speed_t link_speed;
      int link_status;
    } link_event;
  } event_data;
  int severity;
} virtchnl_pf_event_t;

clib_error_t *
avf_recv_from_pf (vlib_main_t * vm, avf_device_t * ad, u16 slot)
{
  void *buf = ad->arq_bufs + slot * AVF_MBOX_BUF_SZ;
  avf_aq_desc_t *d = &ad->arq[slot];

  avf_log_debug ("slot %u opcode %x v_opcode %x v_retval %d flags 0x%x",
		 slot, d->opcode, d->v_opcode, d->retval, d->flags);
  if (d->datalen)
    avf_log_debug ("  %U", format_hexdump, buf, d->datalen);

  if (d->v_opcode == VIRTCHNL_OP_VERSION)
    {
      virtchnl_version_info_t *v = buf;
      avf_log_debug ("version %d.%d", v->major, v->minor);
    }
  else if (d->v_opcode == VIRTCHNL_OP_GET_VF_RESOURCES)
    {
      virtchnl_vf_resource_t *r = buf;
      virtchnl_vsi_resource_t *v = &r->vsi_res[0];
      avf_log_debug ("num_vsis %u num_queue_pairs %u max_vectors %u "
		     "max_mtu %u vf_offload_flags 0x%x",
		     r->num_vsis, r->num_queue_pairs, r->max_vectors,
		     r->max_mtu, r->vf_offload_flags);
      avf_log_debug ("  vsi 0 num_queue_pairs %u vsi_type %u "
		     "qset_handle %u default_mac_addr %U",
		     v->num_queue_pairs, v->vsi_type,
		     v->qset_handle, format_hex_bytes, v->default_mac_addr,
		     6);
    }
  else if (d->v_opcode == VIRTCHNL_OP_EVENT)
    {
      virtchnl_pf_event_t *e = buf;
      if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	avf_log_debug
	  ("link change event severity %d link_speed %d link_status %d",
	   e->event, e->severity, e->event_data.link_event.link_speed,
	   e->event_data.link_event.link_status);
      else
	avf_log_debug ("event %d severity %d", e->event, e->severity);
    }
  else
    avf_log_debug ("unknown opcode %u", d->v_opcode);

  return 0;
}

void
avf_process_one_device (vlib_main_t * vm, avf_device_t * ad)
{
  clib_error_t *error;
  u32 r;

  if (ad->flags & AVF_DEVICE_F_ERROR)
    return;

  if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
    if ((error = avf_device_init (vm, ad)))
      {
	clib_error_report (error);
	goto error;
      }


  r = avf_get_u32 (ad->bar0, AVF_ARQLEN);
  if ((r & 0xf0000000) != 0x80000000)
    {
      avf_log_debug ("arq not enabled, arqlen = 0x%x", r);
      goto error;
    }

  r = avf_get_u32 (ad->bar0, AVF_ATQLEN);
  if ((r & 0xf0000000) != 0x80000000)
    {
      avf_log_debug ("atq not enabled, atqlen = 0x%x", r);
      goto error;
    }

  r = avf_get_u32 (ad->bar0, AVF_ARQH);
  while (ad->arq_next_slot != r)
    {
      avf_recv_from_pf (vm, ad, ad->arq_next_slot);
      ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_MBOX_LEN;
    }

  return;

error:
  ad->flags |= AVF_DEVICE_F_ERROR;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  avf_device_t *ad;

  while (1)
    {
      vlib_process_suspend (vm, 3.0);
      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
	  avf_process_one_device (vm, ad);
        });
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_process_node, static)  = {
  .function = avf_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "avf-process",
};
/* *INDENT-ON* */

static void
avf_pci_intr_handler (vlib_pci_dev_handle_t h)
{
  clib_warning ("int");
}

static clib_error_t *
avf_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  clib_error_t *error = 0;
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  //vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

  pool_get (am->devices, ad);
  ad->pci_dev_handle = h;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_resource (h, 0, &ad->bar0)))
    goto error;

  error = vlib_physmem_region_alloc (vm, "avf_pool", 2 << 20, 0,
				     VLIB_PHYSMEM_F_INIT_MHEAP,
				     &am->physmem_region);
  if (error)
    goto error;
  ad->atq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) * AVF_MBOX_LEN,
					64);
  if (error)
    goto error;

  ad->arq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) * AVF_MBOX_LEN,
					64);
  if (error)
    goto error;

  ad->atq_bufs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					     AVF_MBOX_BUF_SZ * AVF_MBOX_LEN,
					     64);
  if (error)
    goto error;

  ad->arq_bufs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					     AVF_MBOX_BUF_SZ * AVF_MBOX_LEN,
					     64);
  if (error)
    goto error;

  error = vlib_pci_intr_enable (h);

  if (error == 0)
    return 0;

error:
  if (ad->atq)
    vlib_physmem_free (vm, am->physmem_region, ad->atq);
  if (ad->arq)
    vlib_physmem_free (vm, am->physmem_region, ad->arq);
  if (ad->atq_bufs)
    vlib_physmem_free (vm, am->physmem_region, ad->atq_bufs);
  if (ad->arq_bufs)
    vlib_physmem_free (vm, am->physmem_region, ad->arq_bufs);
  memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
  return error;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (avf_pci_device_registration,static) = {
  .init_function = avf_pci_init,
  .interrupt_handler = avf_pci_intr_handler,
  .supported_devices = {
    { .vendor_id = 0x8086, .device_id = 0x154c, },
    { 0 },
  },
};
  /* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (avf_device_class,) =
{
  .name = "Adaptive Virtual Function (AVF) interface",
};
/* *INDENT-ON* */

clib_error_t *
avf_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, pci_bus_init)))
    return error;


  return 0;
}

VLIB_INIT_FUNCTION (avf_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
