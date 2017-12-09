/*
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
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

typedef struct
{
  u32 size;
  union {
      u32 ctl;
      struct {
	  u32 int_en:1;
	  u32 src_snoop_dis:1;
	  u32 dst_snoop_dis:1;
	  u32 compl_write:1;
	  u32 fence:1;
	  u32 nt:1;
	  u32 src_pg_brk:1;
	  u32 dst_pg_brk:1;
	  u32 bundle:1;
	  u32 dest_dca:1;
	  u32 hint:1;
	  u32 rsvd2:13;
	  u32 op:8;
      } ctl_f;
  };
  u64 src_addr;
  u64 dst_addr;
  u64 next_desc;
  u64 next_src_addr;
  u64 next_dst_addr;
  u64 reserved[2];
} cbdma_desc_t;

STATIC_ASSERT_SIZEOF (cbdma_desc_t, 64);

typedef struct
{
  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar;
} cbdma_channel_t;

typedef struct
{
  cbdma_channel_t * channels;
} cbdma_main_t;

cbdma_main_t cbdma_main;

static inline u32
cbdma_get_bits (void *start, int offset, int first, int last)
{
  u32 value =  * ((u32 *) ((u8 *) start + offset));
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
cbdma_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
cbdma_set_u64 (void *start, int offset, u64 value)
{
  (*(u64 *) (((u8 *) start) + offset)) = value;
}

static inline u64
cbdma_get_u64 (void *start, int offset)
{
  return (*(u64 *) (((u8 *) start) + offset));
}

#define foreach_cbdma_reg \
  _(0x00, 4, 0, CHANCNT, num_chan) \
  _(0x01, 4, 0, XFERCAP, trans_size) \
  _(0x03, 3, 3, INTRCTRL, MSIX_VECCTRL) \
  _(0x03, 2, 2, INTRCTRL, intp) \
  _(0x03, 1, 1, INTRCTRL, intp_sts) \
  _(0x03, 0, 0, INTRCTRL, Mstr_intp_En) \
  _(0x04, 0, 0, ATTNSTATUS, ChanAttn) \
  _(0x08, 7, 4, CBVER, mjrver) \
  _(0x08, 3, 0, CBVER, mnrver) \
  _(0x0c, 15, 15, INTRDELAY, Interrupt_Coalescing_Supported) \
  _(0x0c, 13, 0, INTRDELAY, Interrupt_Delay_Time) \
  _(0x0e, 3, 3, CS_STATUS, Address_Remapping) \
  _(0x0e, 2, 2, CS_STATUS, Memory_Bypass) \
  _(0x0e, 1, 1, CS_STATUS, MMIO_Restriction) \
  _(0x10, 27, 27, DMACAPABILITY, InterVM_Supported) \
  _(0x10, 25, 25, DMACAPABILITY, BlockFill_NULL_Supported) \
  _(0x10, 24, 24, DMACAPABILITY, NoST) \
  _(0x10, 10, 10, DMACAPABILITY, DIF) \
  _(0x10, 9, 9, DMACAPABILITY, XOR_RAID6) \
  _(0x10, 8, 8, DMACAPABILITY, XOR_RAID5) \
  _(0x10, 7, 7, DMACAPABILITY, Extended_APIC_ID) \
  _(0x10, 6, 6, DMACAPABILITY, Block_Fill) \
  _(0x10, 5, 5, DMACAPABILITY, Move_CRC) \
  _(0x10, 4, 4, DMACAPABILITY, DCA) \
  _(0x10, 3, 3, DMACAPABILITY, XOR) \
  _(0x10, 2, 2, DMACAPABILITY, Marker_Skipping) \
  _(0x10, 1, 1, DMACAPABILITY, CRC) \
  _(0x10, 0, 0, DMACAPABILITY, Page_Break) \
  _(0x14, 15, 0, DCAOFFSET, DCAREGPTR) \
  _(0x100, 7, 4, DCA_VER, Major_Revision) \
  _(0x100, 3, 0, DCA_VER, Minor_Revision) \


u8 *
format_cbdma_registers (u8 * s, va_list * args)
{
  void *bar = va_arg (*args, void *);
  u32 val;

#define _(off, msb, lsb, reg, field) \
  val = cbdma_get_bits (bar, off, msb, lsb); \
  s = format (s, "%-40s0x%x\n", #reg "." #field, val);

  foreach_cbdma_reg
#undef _

  return s;
}

static clib_error_t *
cbdma_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  cbdma_main_t *cm = &cbdma_main;
  cbdma_channel_t *cc;
  void * bar;
  clib_error_t *error = 0;

  if ((error = vlib_pci_map_resource (h, 0, (void *) &bar)))
    goto error;

#if 0
  fformat (stdout, "\n%U\n", format_hexdump, bar, 0x128);
  fformat (stdout, "\n%U\n", format_cbdma_registers, bar);
#endif

  vec_add2 (cm->channels, cc, 1);
  cc->bar = bar;
  cc->pci_dev_handle = h;

  error = vlib_pci_bus_master_enable (h);

error:
  return error;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (cbdma_pci_device_registration, static) = {
  .init_function = cbdma_pci_init,
  .supported_devices = {
    { .vendor_id = 0x8086, .device_id = 0x2021, },
    { .vendor_id = 0x8086, .device_id = 0x6f20, },
    { .vendor_id = 0x8086, .device_id = 0x6f21, },
    { 0 },
  },
};

/* *INDENT-ON* */


static u8 *
format_cbdma_channel (u8 * s, va_list * args)
{
  cbdma_channel_t *cc = va_arg (*args, cbdma_channel_t*);

  s = format (s, "%U: version %u.%u max-transfer-size %u dca-version %u.%u\n",
	      format_vlib_pci_addr, vlib_pci_get_addr (cc->pci_dev_handle),
	      cbdma_get_bits (cc->bar, 0x08, 7, 4),
	      cbdma_get_bits (cc->bar, 0x08, 3, 0),
	      1 << cbdma_get_bits (cc->bar, 0x01, 4, 0),
	      cbdma_get_bits (cc->bar, 0x100, 7, 4),
	      cbdma_get_bits (cc->bar, 0x100, 3, 0));

  return s;
}


static clib_error_t *
show_cbdma_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cbdma_main_t *cm = &cbdma_main;
  cbdma_channel_t *cc;

  pool_foreach (cc, cm->channels, (
  {
    vlib_cli_output (vm, "\n%U\n",
		     format_cbdma_channel, cc);

  }));
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cbdma_interface, static) =
{
  .path = "show cbdma",
  .short_help = "show cbdma",
  .function = show_cbdma_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_cbdma_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *err = 0;
  cbdma_desc_t *d;
  u8 *src, *dst;
  int size = 1024, i;
  u8 c = 0;
  cbdma_main_t *cm = &cbdma_main;
  cbdma_channel_t *cc = vec_elt_at_index (cm->channels, 0);;
  vlib_physmem_region_index_t pr;
  err = vlib_physmem_region_alloc (vm, "cbdma test", 8 << 20, 0,
				   VLIB_PHYSMEM_F_INIT_MHEAP, &pr);
  if (err)
    return err;

  d = vlib_physmem_alloc_aligned (vm, pr, &err, 32 * sizeof (cbdma_desc_t), 64);
  if (err)
    return err;

  src = vlib_physmem_alloc_aligned (vm, pr, &err, size, 64);
  if (err)
    return err;

  dst = vlib_physmem_alloc_aligned (vm, pr, &err, size, 64);
  if (err)
    return err;

  vlib_cli_output (vm, " desc %llx src %llx dst %llx",
		   vlib_physmem_virtual_to_physical (vm, pr, d),
		   vlib_physmem_virtual_to_physical (vm, pr, src),
		   vlib_physmem_virtual_to_physical (vm, pr, dst));

  for (i = 0; i < size; i++)
    src[i] = c++;

  /* descriptor */
  d[0].ctl = 0;
//  d[0].ctl_f.nt = 1;
//  d[0].ctl_f.int_en= 1;
  d[0].size = 64;
  d[0].src_addr = vlib_physmem_virtual_to_physical (vm, pr, src);
  d[0].dst_addr = vlib_physmem_virtual_to_physical (vm, pr, dst);
//  d[0].next_desc = vlib_physmem_virtual_to_physical (vm, pr, d) + 64;

  vlib_cli_output (vm, "desc   %U", format_hexdump, d, 64);

  vlib_cli_output (vm, "src    %U", format_hexdump, src, 64);
  vlib_cli_output (vm, "before %U", format_hexdump, dst, 64);
  /* reset */
  cbdma_set_u32 (cc->bar, 0x84, 1 << 5);

  /* set CHAINADDR */
  u64 hw = vlib_physmem_virtual_to_physical (vm, pr, d);
  cbdma_set_u32 (cc->bar, 0x90, hw & 0x00000000FFFFFFFF);
  cbdma_set_u32 (cc->bar, 0x94, hw >> 32);

  vlib_cli_output(vm, "chansts.state %u", cbdma_get_bits (cc->bar, 0x88, 2, 0));
  vlib_cli_output(vm, "chansts.cmpdscaddr %llx", cbdma_get_u64 (cc->bar, 0x88));
#if 1
  CLIB_MEMORY_STORE_BARRIER();
  /* set DMACOUNT */
  cbdma_set_u32(cc->bar, 0x86, 1);
#endif
  vlib_cli_output(vm, "chansts.state %u", cbdma_get_bits (cc->bar, 0x88, 2, 0));
  vlib_cli_output(vm, "chansts.cmpdscaddr %llx", cbdma_get_u64 (cc->bar, 0x88));

  vlib_cli_output (vm, "after  %U", format_hexdump, dst, 64);

  vlib_physmem_free (vm, pr, (void *) d);
  vlib_physmem_free (vm, pr, (void *) src);
  vlib_physmem_free (vm, pr, (void *) dst);
  vlib_physmem_region_free (vm, pr);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_cbdma, static) =
{
  .path = "test cbdma",
  .short_help = "test cbdma",
  .function = test_cbdma_fn,
};
/* *INDENT-ON* */


clib_error_t *
cbdma_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (cbdma_init);

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Intel DirectData (Crystal Beach) DMA Plugin",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
