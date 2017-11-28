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
/*
 * pci.h: PCI definitions.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_pci_config_h
#define included_vlib_pci_config_h

#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>

typedef enum
{
  PCI_CLASS_NOT_DEFINED = 0x0000,
  PCI_CLASS_NOT_DEFINED_VGA = 0x0001,

  PCI_CLASS_STORAGE_SCSI = 0x0100,
  PCI_CLASS_STORAGE_IDE = 0x0101,
  PCI_CLASS_STORAGE_FLOPPY = 0x0102,
  PCI_CLASS_STORAGE_IPI = 0x0103,
  PCI_CLASS_STORAGE_RAID = 0x0104,
  PCI_CLASS_STORAGE_OTHER = 0x0180,
  PCI_CLASS_STORAGE = 0x0100,

  PCI_CLASS_NETWORK_ETHERNET = 0x0200,
  PCI_CLASS_NETWORK_TOKEN_RING = 0x0201,
  PCI_CLASS_NETWORK_FDDI = 0x0202,
  PCI_CLASS_NETWORK_ATM = 0x0203,
  PCI_CLASS_NETWORK_OTHER = 0x0280,
  PCI_CLASS_NETWORK = 0x0200,

  PCI_CLASS_DISPLAY_VGA = 0x0300,
  PCI_CLASS_DISPLAY_XGA = 0x0301,
  PCI_CLASS_DISPLAY_3D = 0x0302,
  PCI_CLASS_DISPLAY_OTHER = 0x0380,
  PCI_CLASS_DISPLAY = 0x0300,

  PCI_CLASS_MULTIMEDIA_VIDEO = 0x0400,
  PCI_CLASS_MULTIMEDIA_AUDIO = 0x0401,
  PCI_CLASS_MULTIMEDIA_PHONE = 0x0402,
  PCI_CLASS_MULTIMEDIA_OTHER = 0x0480,
  PCI_CLASS_MULTIMEDIA = 0x0400,

  PCI_CLASS_MEMORY_RAM = 0x0500,
  PCI_CLASS_MEMORY_FLASH = 0x0501,
  PCI_CLASS_MEMORY_OTHER = 0x0580,
  PCI_CLASS_MEMORY = 0x0500,

  PCI_CLASS_BRIDGE_HOST = 0x0600,
  PCI_CLASS_BRIDGE_ISA = 0x0601,
  PCI_CLASS_BRIDGE_EISA = 0x0602,
  PCI_CLASS_BRIDGE_MC = 0x0603,
  PCI_CLASS_BRIDGE_PCI = 0x0604,
  PCI_CLASS_BRIDGE_PCMCIA = 0x0605,
  PCI_CLASS_BRIDGE_NUBUS = 0x0606,
  PCI_CLASS_BRIDGE_CARDBUS = 0x0607,
  PCI_CLASS_BRIDGE_RACEWAY = 0x0608,
  PCI_CLASS_BRIDGE_OTHER = 0x0680,
  PCI_CLASS_BRIDGE = 0x0600,

  PCI_CLASS_COMMUNICATION_SERIAL = 0x0700,
  PCI_CLASS_COMMUNICATION_PARALLEL = 0x0701,
  PCI_CLASS_COMMUNICATION_MULTISERIAL = 0x0702,
  PCI_CLASS_COMMUNICATION_MODEM = 0x0703,
  PCI_CLASS_COMMUNICATION_OTHER = 0x0780,
  PCI_CLASS_COMMUNICATION = 0x0700,

  PCI_CLASS_SYSTEM_PIC = 0x0800,
  PCI_CLASS_SYSTEM_DMA = 0x0801,
  PCI_CLASS_SYSTEM_TIMER = 0x0802,
  PCI_CLASS_SYSTEM_RTC = 0x0803,
  PCI_CLASS_SYSTEM_PCI_HOTPLUG = 0x0804,
  PCI_CLASS_SYSTEM_OTHER = 0x0880,
  PCI_CLASS_SYSTEM = 0x0800,

  PCI_CLASS_INPUT_KEYBOARD = 0x0900,
  PCI_CLASS_INPUT_PEN = 0x0901,
  PCI_CLASS_INPUT_MOUSE = 0x0902,
  PCI_CLASS_INPUT_SCANNER = 0x0903,
  PCI_CLASS_INPUT_GAMEPORT = 0x0904,
  PCI_CLASS_INPUT_OTHER = 0x0980,
  PCI_CLASS_INPUT = 0x0900,

  PCI_CLASS_DOCKING_GENERIC = 0x0a00,
  PCI_CLASS_DOCKING_OTHER = 0x0a80,
  PCI_CLASS_DOCKING = 0x0a00,

  PCI_CLASS_PROCESSOR_386 = 0x0b00,
  PCI_CLASS_PROCESSOR_486 = 0x0b01,
  PCI_CLASS_PROCESSOR_PENTIUM = 0x0b02,
  PCI_CLASS_PROCESSOR_ALPHA = 0x0b10,
  PCI_CLASS_PROCESSOR_POWERPC = 0x0b20,
  PCI_CLASS_PROCESSOR_MIPS = 0x0b30,
  PCI_CLASS_PROCESSOR_CO = 0x0b40,
  PCI_CLASS_PROCESSOR = 0x0b00,

  PCI_CLASS_SERIAL_FIREWIRE = 0x0c00,
  PCI_CLASS_SERIAL_ACCESS = 0x0c01,
  PCI_CLASS_SERIAL_SSA = 0x0c02,
  PCI_CLASS_SERIAL_USB = 0x0c03,
  PCI_CLASS_SERIAL_FIBER = 0x0c04,
  PCI_CLASS_SERIAL_SMBUS = 0x0c05,
  PCI_CLASS_SERIAL = 0x0c00,

  PCI_CLASS_INTELLIGENT_I2O = 0x0e00,
  PCI_CLASS_INTELLIGENT = 0x0e00,

  PCI_CLASS_SATELLITE_TV = 0x0f00,
  PCI_CLASS_SATELLITE_AUDIO = 0x0f01,
  PCI_CLASS_SATELLITE_VOICE = 0x0f03,
  PCI_CLASS_SATELLITE_DATA = 0x0f04,
  PCI_CLASS_SATELLITE = 0x0f00,

  PCI_CLASS_CRYPT_NETWORK = 0x1000,
  PCI_CLASS_CRYPT_ENTERTAINMENT = 0x1001,
  PCI_CLASS_CRYPT_OTHER = 0x1080,
  PCI_CLASS_CRYPT = 0x1000,

  PCI_CLASS_SP_DPIO = 0x1100,
  PCI_CLASS_SP_OTHER = 0x1180,
  PCI_CLASS_SP = 0x1100,
} pci_device_class_t;

static inline pci_device_class_t
pci_device_class_base (pci_device_class_t c)
{
  return c & ~0xff;
}

/*
 * 0x1000 is the legacy device-id value
 * 0x1041 is (0x1040 + 1), 1 being the Virtio Device ID
 */
#define VIRTIO_PCI_LEGACY_DEVICEID_NET 0x1000
#define VIRTIO_PCI_MODERN_DEVICEID_NET 0x1041

/*
 * Under PCI, each device has 256 bytes of configuration address space,
 * of which the first 64 bytes are standardized as follows:
 */
typedef struct
{
  u16 vendor_id;
  u16 device_id;

  u16 command;
#define PCI_COMMAND_IO		(1 << 0)	/* Enable response in I/O space */
#define PCI_COMMAND_MEMORY	(1 << 1)	/* Enable response in Memory space */
#define PCI_COMMAND_BUS_MASTER	(1 << 2)	/* Enable bus mastering */
#define PCI_COMMAND_SPECIAL	(1 << 3)	/* Enable response to special cycles */
#define PCI_COMMAND_WRITE_INVALIDATE (1 << 4)	/* Use memory write and invalidate */
#define PCI_COMMAND_VGA_PALETTE_SNOOP (1 << 5)
#define PCI_COMMAND_PARITY	(1 << 6)
#define PCI_COMMAND_WAIT 	(1 << 7)	/* Enable address/data stepping */
#define PCI_COMMAND_SERR	(1 << 8)	/* Enable SERR */
#define PCI_COMMAND_BACK_TO_BACK_WRITE (1 << 9)
#define PCI_COMMAND_INTX_DISABLE (1 << 10)	/* INTx Emulation Disable */

  u16 status;
#define PCI_STATUS_INTX_PENDING (1 << 3)
#define PCI_STATUS_CAPABILITY_LIST (1 << 4)
#define PCI_STATUS_66MHZ	(1 << 5)	/* Support 66 Mhz PCI 2.1 bus */
#define PCI_STATUS_UDF		(1 << 6)	/* Support User Definable Features (obsolete) */
#define PCI_STATUS_BACK_TO_BACK_WRITE (1 << 7)	/* Accept fast-back to back */
#define PCI_STATUS_PARITY_ERROR	(1 << 8)	/* Detected parity error */
#define PCI_STATUS_DEVSEL_GET(x) ((x >> 9) & 3)	/* DEVSEL timing */
#define PCI_STATUS_DEVSEL_FAST (0 << 9)
#define PCI_STATUS_DEVSEL_MEDIUM (1 << 9)
#define PCI_STATUS_DEVSEL_SLOW (2 << 9)
#define PCI_STATUS_SIG_TARGET_ABORT (1 << 11)	/* Set on target abort */
#define PCI_STATUS_REC_TARGET_ABORT (1 << 12)	/* Master ack of " */
#define PCI_STATUS_REC_MASTER_ABORT (1 << 13)	/* Set on master abort */
#define PCI_STATUS_SIG_SYSTEM_ERROR (1 << 14)	/* Set when we drive SERR */
#define PCI_STATUS_DETECTED_PARITY_ERROR (1 << 15)

  u8 revision_id;
  u8 programming_interface_class;	/* Reg. Level Programming Interface */

  pci_device_class_t device_class:16;

  u8 cache_size;
  u8 latency_timer;

  u8 header_type;
#define PCI_HEADER_TYPE_NORMAL	0
#define PCI_HEADER_TYPE_BRIDGE 1
#define PCI_HEADER_TYPE_CARDBUS 2

  u8 bist;
#define PCI_BIST_CODE_MASK	0x0f	/* Return result */
#define PCI_BIST_START		0x40	/* 1 to start BIST, 2 secs or less */
#define PCI_BIST_CAPABLE	0x80	/* 1 if BIST capable */
} pci_config_header_t;

/* Byte swap config header. */
always_inline void
pci_config_header_little_to_host (pci_config_header_t * r)
{
  if (!CLIB_ARCH_IS_BIG_ENDIAN)
    return;
#define _(f,t) r->f = clib_byte_swap_##t (r->f)
  _(vendor_id, u16);
  _(device_id, u16);
  _(command, u16);
  _(status, u16);
  _(device_class, u16);
#undef _
}

/* Header type 0 (normal devices) */
typedef struct
{
  pci_config_header_t header;

  /*
   * Base addresses specify locations in memory or I/O space.
   * Decoded size can be determined by writing a value of
   * 0xffffffff to the register, and reading it back. Only
   * 1 bits are decoded.
   */
  u32 base_address[6];

  u16 cardbus_cis;

  u16 subsystem_vendor_id;
  u16 subsystem_id;

  u32 rom_address;
#define PCI_ROM_ADDRESS		0x30	/* Bits 31..11 are address, 10..1 reserved */
#define PCI_ROM_ADDRESS_ENABLE	0x01
#define PCI_ROM_ADDRESS_MASK	(~0x7ffUL)

  u8 first_capability_offset;
    CLIB_PAD_FROM_TO (0x35, 0x3c);

  u8 interrupt_line;
  u8 interrupt_pin;
  u8 min_grant;
  u8 max_latency;

  u8 capability_data[0];
} pci_config_type0_regs_t;

always_inline void
pci_config_type0_little_to_host (pci_config_type0_regs_t * r)
{
  int i;
  if (!CLIB_ARCH_IS_BIG_ENDIAN)
    return;
  pci_config_header_little_to_host (&r->header);
#define _(f,t) r->f = clib_byte_swap_##t (r->f)
  for (i = 0; i < ARRAY_LEN (r->base_address); i++)
    _(base_address[i], u32);
  _(cardbus_cis, u16);
  _(subsystem_vendor_id, u16);
  _(subsystem_id, u16);
  _(rom_address, u32);
#undef _
}

/* Header type 1 (PCI-to-PCI bridges) */
typedef struct
{
  pci_config_header_t header;

  u32 base_address[2];

  /* Primary/secondary bus number. */
  u8 primary_bus;
  u8 secondary_bus;

  /* Highest bus number behind the bridge */
  u8 subordinate_bus;

  u8 secondary_bus_latency_timer;

  /* I/O range behind bridge. */
  u8 io_base, io_limit;

  /* Secondary status register, only bit 14 used */
  u16 secondary_status;

  /* Memory range behind bridge in units of 64k bytes. */
  u16 memory_base, memory_limit;
#define PCI_MEMORY_RANGE_TYPE_MASK 0x0fUL
#define PCI_MEMORY_RANGE_MASK	(~0x0fUL)

  u16 prefetchable_memory_base, prefetchable_memory_limit;
#define PCI_PREF_RANGE_TYPE_MASK 0x0fUL
#define PCI_PREF_RANGE_TYPE_32	0x00
#define PCI_PREF_RANGE_TYPE_64	0x01
#define PCI_PREF_RANGE_MASK	(~0x0fUL)

  u32 prefetchable_memory_base_upper_32bits;
  u32 prefetchable_memory_limit_upper_32bits;
  u16 io_base_upper_16bits;
  u16 io_limit_upper_16bits;

  /* Same as for type 0. */
  u8 capability_list_offset;
    CLIB_PAD_FROM_TO (0x35, 0x37);

  u32 rom_address;
    CLIB_PAD_FROM_TO (0x3c, 0x3e);

  u16 bridge_control;
#define PCI_BRIDGE_CTL_PARITY	0x01	/* Enable parity detection on secondary interface */
#define PCI_BRIDGE_CTL_SERR	0x02	/* The same for SERR forwarding */
#define PCI_BRIDGE_CTL_NO_ISA	0x04	/* Disable bridging of ISA ports */
#define PCI_BRIDGE_CTL_VGA	0x08	/* Forward VGA addresses */
#define PCI_BRIDGE_CTL_MASTER_ABORT 0x20	/* Report master aborts */
#define PCI_BRIDGE_CTL_BUS_RESET 0x40	/* Secondary bus reset */
#define PCI_BRIDGE_CTL_FAST_BACK 0x80	/* Fast Back2Back enabled on secondary interface */

  u8 capability_data[0];
} pci_config_type1_regs_t;

always_inline void
pci_config_type1_little_to_host (pci_config_type1_regs_t * r)
{
  int i;
  if (!CLIB_ARCH_IS_BIG_ENDIAN)
    return;
  pci_config_header_little_to_host (&r->header);
#define _(f,t) r->f = clib_byte_swap_##t (r->f)
  for (i = 0; i < ARRAY_LEN (r->base_address); i++)
    _(base_address[i], u32);
  _(secondary_status, u16);
  _(memory_base, u16);
  _(memory_limit, u16);
  _(prefetchable_memory_base, u16);
  _(prefetchable_memory_limit, u16);
  _(prefetchable_memory_base_upper_32bits, u32);
  _(prefetchable_memory_limit_upper_32bits, u32);
  _(io_base_upper_16bits, u16);
  _(io_limit_upper_16bits, u16);
  _(rom_address, u32);
  _(bridge_control, u16);
#undef _
}

/* Capabilities. */
typedef enum pci_capability_type
{
  /* Power Management */
  PCI_CAP_ID_PM = 1,

  /* Accelerated Graphics Port */
  PCI_CAP_ID_AGP = 2,

  /* Vital Product Data */
  PCI_CAP_ID_VPD = 3,

  /* Slot Identification */
  PCI_CAP_ID_SLOTID = 4,

  /* Message Signalled Interrupts */
  PCI_CAP_ID_MSI = 5,

  /* CompactPCI HotSwap */
  PCI_CAP_ID_CHSWP = 6,

  /* PCI-X */
  PCI_CAP_ID_PCIX = 7,

  /* Hypertransport. */
  PCI_CAP_ID_HYPERTRANSPORT = 8,

  /* PCI Standard Hot-Plug Controller */
  PCI_CAP_ID_SHPC = 0xc,

  /* PCI Express */
  PCI_CAP_ID_PCIE = 0x10,

  /* MSI-X */
  PCI_CAP_ID_MSIX = 0x11,
} pci_capability_type_t;

/* Common header for capabilities. */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     enum pci_capability_type type:8;
		     u8 next_offset;}) pci_capability_regs_t;
/* *INDENT-ON* */

always_inline void *
pci_config_find_capability (pci_config_type0_regs_t * t, int cap_type)
{
  pci_capability_regs_t *c;
  u32 next_offset;
  u32 ttl = 48;

  if (!(t->header.status & PCI_STATUS_CAPABILITY_LIST))
    return 0;

  next_offset = t->first_capability_offset;
  while (ttl-- && next_offset >= 0x40)
    {
      c = (void *) t + (next_offset & ~3);
      if ((u8) c->type == 0xff)
	break;
      if (c->type == cap_type)
	return c;
      next_offset = c->next_offset;
    }
  return 0;
}

/* Power Management Registers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 capabilities;
#define PCI_PM_CAP_VER_MASK	0x0007	/* Version */
#define PCI_PM_CAP_PME_CLOCK	0x0008	/* PME clock required */
#define PCI_PM_CAP_RESERVED  0x0010	/* Reserved field */
#define PCI_PM_CAP_DSI		0x0020	/* Device specific initialization */
#define PCI_PM_CAP_AUX_POWER	0x01C0	/* Auxilliary power support mask */
#define PCI_PM_CAP_D1		0x0200	/* D1 power state support */
#define PCI_PM_CAP_D2		0x0400	/* D2 power state support */
#define PCI_PM_CAP_PME		0x0800	/* PME pin supported */
#define PCI_PM_CAP_PME_MASK  0xF800	/* PME Mask of all supported states */
#define PCI_PM_CAP_PME_D0   0x0800	/* PME# from D0 */
#define PCI_PM_CAP_PME_D1   0x1000	/* PME# from D1 */
#define PCI_PM_CAP_PME_D2   0x2000	/* PME# from D2 */
#define PCI_PM_CAP_PME_D3   0x4000	/* PME# from D3 (hot) */
#define PCI_PM_CAP_PME_D3cold 0x8000	/* PME# from D3 (cold) */
		     u16 control;
#define PCI_PM_CTRL_STATE_MASK	0x0003	/* Current power state (D0 to D3) */
#define PCI_PM_CTRL_PME_ENABLE	0x0100	/* PME pin enable */
#define PCI_PM_CTRL_DATA_SEL_MASK	0x1e00	/* Data select (??) */
#define PCI_PM_CTRL_DATA_SCALE_MASK	0x6000	/* Data scale (??) */
#define PCI_PM_CTRL_PME_STATUS	0x8000	/* PME pin status */
		     u8 extensions;
#define PCI_PM_PPB_B2_B3	0x40	/* Stop clock when in D3hot (??) */
#define PCI_PM_BPCC_ENABLE	0x80	/* Bus power/clock control enable (??) */
		     u8 data;}) pci_power_management_regs_t;
/* *INDENT-ON* */

/* AGP registers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u8 version;
		     u8 rest_of_capability_flags; u32 status; u32 command;
		     /* Command & status common bits. */
#define PCI_AGP_RQ_MASK	0xff000000	/* Maximum number of requests - 1 */
#define PCI_AGP_SBA	0x0200	/* Sideband addressing supported */
#define PCI_AGP_64BIT	0x0020	/* 64-bit addressing supported */
#define PCI_AGP_ALLOW_TRANSACTIONS 0x0100	/* Allow processing of AGP transactions */
#define PCI_AGP_FW	0x0010	/* FW transfers supported/forced */
#define PCI_AGP_RATE4	0x0004	/* 4x transfer rate supported */
#define PCI_AGP_RATE2	0x0002	/* 2x transfer rate supported */
#define PCI_AGP_RATE1	0x0001	/* 1x transfer rate supported */
		     }) pci_agp_regs_t;
/* *INDENT-ON* */

/* Vital Product Data */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 address;
#define PCI_VPD_ADDR_MASK	0x7fff	/* Address mask */
#define PCI_VPD_ADDR_F		0x8000	/* Write 0, 1 indicates completion */
		     u32 data;}) pci_vpd_regs_t;
/* *INDENT-ON* */

/* Slot Identification */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u8 esr;
#define PCI_SID_ESR_NSLOTS	0x1f	/* Number of expansion slots available */
#define PCI_SID_ESR_FIC	0x20	/* First In Chassis Flag */
		     u8 chassis;}) pci_sid_regs_t;
/* *INDENT-ON* */

/* Message Signalled Interrupts registers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 flags;
#define PCI_MSI_FLAGS_ENABLE	(1 << 0)	/* MSI feature enabled */
#define PCI_MSI_FLAGS_GET_MAX_QUEUE_SIZE(x) ((x >> 1) & 0x7)
#define PCI_MSI_FLAGS_MAX_QUEUE_SIZE(x)     (((x) & 0x7) << 1)
#define PCI_MSI_FLAGS_GET_QUEUE_SIZE(x) ((x >> 4) & 0x7)
#define PCI_MSI_FLAGS_QUEUE_SIZE(x)     (((x) & 0x7) << 4)
#define PCI_MSI_FLAGS_64BIT	(1 << 7)	/* 64-bit addresses allowed */
#define PCI_MSI_FLAGS_MASKBIT	(1 << 8)	/* 64-bit mask bits allowed */
		     u32 address; u32 data; u32 mask_bits;}) pci_msi32_regs_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 flags;
		     u32 address[2];
		     u32 data; u32 mask_bits;}) pci_msi64_regs_t;
/* *INDENT-ON* */

/* CompactPCI Hotswap Register */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 control_status;
#define PCI_CHSWP_DHA		0x01	/* Device Hiding Arm */
#define PCI_CHSWP_EIM		0x02	/* ENUM# Signal Mask */
#define PCI_CHSWP_PIE		0x04	/* Pending Insert or Extract */
#define PCI_CHSWP_LOO		0x08	/* LED On / Off */
#define PCI_CHSWP_PI		0x30	/* Programming Interface */
#define PCI_CHSWP_EXT		0x40	/* ENUM# status - extraction */
#define PCI_CHSWP_INS		0x80	/* ENUM# status - insertion */
		     }) pci_chswp_regs_t;
/* *INDENT-ON* */

/* PCIX registers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 command;
#define PCIX_CMD_DPERR_E	0x0001	/* Data Parity Error Recovery Enable */
#define PCIX_CMD_ERO		0x0002	/* Enable Relaxed Ordering */
#define PCIX_CMD_MAX_READ	0x000c	/* Max Memory Read Byte Count */
#define PCIX_CMD_MAX_SPLIT	0x0070	/* Max Outstanding Split Transactions */
#define PCIX_CMD_VERSION(x) 	(((x) >> 12) & 3)	/* Version */
		     u32 status;
#define PCIX_STATUS_DEVFN	0x000000ff	/* A copy of devfn */
#define PCIX_STATUS_BUS	0x0000ff00	/* A copy of bus nr */
#define PCIX_STATUS_64BIT	0x00010000	/* 64-bit device */
#define PCIX_STATUS_133MHZ	0x00020000	/* 133 MHz capable */
#define PCIX_STATUS_SPL_DISC	0x00040000	/* Split Completion Discarded */
#define PCIX_STATUS_UNX_SPL	0x00080000	/* Unexpected Split Completion */
#define PCIX_STATUS_COMPLEX	0x00100000	/* Device Complexity */
#define PCIX_STATUS_MAX_READ	0x00600000	/* Designed Max Memory Read Count */
#define PCIX_STATUS_MAX_SPLIT	0x03800000	/* Designed Max Outstanding Split Transactions */
#define PCIX_STATUS_MAX_CUM	0x1c000000	/* Designed Max Cumulative Read Size */
#define PCIX_STATUS_SPL_ERR	0x20000000	/* Rcvd Split Completion Error Msg */
#define PCIX_STATUS_266MHZ	0x40000000	/* 266 MHz capable */
#define PCIX_STATUS_533MHZ	0x80000000	/* 533 MHz capable */
		     }) pcix_config_regs_t;
/* *INDENT-ON* */

static inline int
pcie_size_to_code (int bytes)
{
  ASSERT (is_pow2 (bytes));
  ASSERT (bytes <= 4096);
  return min_log2 (bytes) - 7;
}

static inline int
pcie_code_to_size (int code)
{
  int size = 1 << (code + 7);
  ASSERT (size <= 4096);
  return size;
}

/* PCI Express capability registers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pci_capability_regs_t header; u16 pcie_capabilities;
#define PCIE_CAP_VERSION(x)	(((x) >> 0) & 0xf)
#define PCIE_CAP_DEVICE_TYPE(x)	(((x) >> 4) & 0xf)
#define PCIE_DEVICE_TYPE_ENDPOINT 0
#define PCIE_DEVICE_TYPE_LEGACY_ENDPOINT 1
#define PCIE_DEVICE_TYPE_ROOT_PORT 4
		     /* Upstream/downstream port of PCI Express switch. */
#define PCIE_DEVICE_TYPE_SWITCH_UPSTREAM 5
#define PCIE_DEVICE_TYPE_SWITCH_DOWNSTREAM 6
#define PCIE_DEVICE_TYPE_PCIE_TO_PCI_BRIDGE 7
#define PCIE_DEVICE_TYPE_PCI_TO_PCIE_BRIDGE 8
		     /* Root complex integrated endpoint. */
#define PCIE_DEVICE_TYPE_ROOT_COMPLEX_ENDPOINT 9
#define PCIE_DEVICE_TYPE_ROOT_COMPLEX_EVENT_COLLECTOR 10
#define PCIE_CAP_SLOW_IMPLEMENTED (1 << 8)
#define PCIE_CAP_MSI_IRQ(x) (((x) >> 9) & 0x1f)
		     u32 dev_capabilities;
#define PCIE_DEVCAP_MAX_PAYLOAD(x) (128 << (((x) >> 0) & 0x7))
#define PCIE_DEVCAP_PHANTOM_BITS(x) (((x) >> 3) & 0x3)
#define PCIE_DEVCAP_EXTENTED_TAG (1 << 5)
#define PCIE_DEVCAP_L0S	0x1c0	/* L0s Acceptable Latency */
#define PCIE_DEVCAP_L1	0xe00	/* L1 Acceptable Latency */
#define PCIE_DEVCAP_ATN_BUT	0x1000	/* Attention Button Present */
#define PCIE_DEVCAP_ATN_IND	0x2000	/* Attention Indicator Present */
#define PCIE_DEVCAP_PWR_IND	0x4000	/* Power Indicator Present */
#define PCIE_DEVCAP_PWR_VAL	0x3fc0000	/* Slot Power Limit Value */
#define PCIE_DEVCAP_PWR_SCL	0xc000000	/* Slot Power Limit Scale */
		     u16 dev_control;
#define PCIE_CTRL_CERE	0x0001	/* Correctable Error Reporting En. */
#define PCIE_CTRL_NFERE	0x0002	/* Non-Fatal Error Reporting Enable */
#define PCIE_CTRL_FERE	0x0004	/* Fatal Error Reporting Enable */
#define PCIE_CTRL_URRE	0x0008	/* Unsupported Request Reporting En. */
#define PCIE_CTRL_RELAX_EN 0x0010	/* Enable relaxed ordering */
#define PCIE_CTRL_MAX_PAYLOAD(n) (((n) & 7) << 5)
#define PCIE_CTRL_EXT_TAG	0x0100	/* Extended Tag Field Enable */
#define PCIE_CTRL_PHANTOM	0x0200	/* Phantom Functions Enable */
#define PCIE_CTRL_AUX_PME	0x0400	/* Auxiliary Power PM Enable */
#define PCIE_CTRL_NOSNOOP_EN	0x0800	/* Enable No Snoop */
#define PCIE_CTRL_MAX_READ_REQUEST(n) (((n) & 7) << 12)
		     u16 dev_status;
#define PCIE_DEVSTA_AUXPD	0x10	/* AUX Power Detected */
#define PCIE_DEVSTA_TRPND	0x20	/* Transactions Pending */
		     u32 link_capabilities; u16 link_control; u16 link_status;
		     u32 slot_capabilities;
		     u16 slot_control; u16 slot_status; u16 root_control;
#define PCIE_RTCTL_SECEE	0x01	/* System Error on Correctable Error */
#define PCIE_RTCTL_SENFEE	0x02	/* System Error on Non-Fatal Error */
#define PCIE_RTCTL_SEFEE	0x04	/* System Error on Fatal Error */
#define PCIE_RTCTL_PMEIE	0x08	/* PME Interrupt Enable */
#define PCIE_RTCTL_CRSSVE	0x10	/* CRS Software Visibility Enable */
		     u16 root_capabilities;
		     u32 root_status;
		     u32 dev_capabilities2;
		     u16 dev_control2;
		     u16 dev_status2;
		     u32 link_capabilities2;
		     u16 link_control2;
		     u16 link_status2;
		     u32 slot_capabilities2; u16 slot_control2;
		     u16 slot_status2;}) pcie_config_regs_t;
/* *INDENT-ON* */

/* PCI express extended capabilities. */
typedef enum pcie_capability_type
{
  PCIE_CAP_ADVANCED_ERROR = 1,
  PCIE_CAP_VC = 2,
  PCIE_CAP_DSN = 3,
  PCIE_CAP_PWR = 4,
} pcie_capability_type_t;

/* Common header for capabilities. */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
enum pcie_capability_type type:16; u16 version: 4; u16 next_capability:12;})
  /* *INDENT-ON* */
pcie_capability_regs_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
		     {
		     pcie_capability_regs_t header; u32 uncorrectable_status;
#define PCIE_ERROR_UNC_LINK_TRAINING 		(1 << 0)
#define PCIE_ERROR_UNC_DATA_LINK_PROTOCOL 	(1 << 4)
#define PCIE_ERROR_UNC_SURPRISE_DOWN		(1 << 5)
#define PCIE_ERROR_UNC_POISONED_TLP		(1 << 12)
#define PCIE_ERROR_UNC_FLOW_CONTROL		(1 << 13)
#define PCIE_ERROR_UNC_COMPLETION_TIMEOUT	(1 << 14)
#define PCIE_ERROR_UNC_COMPLETER_ABORT		(1 << 15)
#define PCIE_ERROR_UNC_UNEXPECTED_COMPLETION	(1 << 16)
#define PCIE_ERROR_UNC_RX_OVERFLOW		(1 << 17)
#define PCIE_ERROR_UNC_MALFORMED_TLP		(1 << 18)
#define PCIE_ERROR_UNC_CRC_ERROR		(1 << 19)
#define PCIE_ERROR_UNC_UNSUPPORTED_REQUEST	(1 << 20)
		     u32 uncorrectable_mask;
		     u32 uncorrectable_severity; u32 correctable_status;
#define PCIE_ERROR_COR_RX_ERROR		(1 << 0)
#define PCIE_ERROR_COR_BAD_TLP		(1 << 6)
#define PCIE_ERROR_COR_BAD_DLLP		(1 << 7)
#define PCIE_ERROR_COR_REPLAY_ROLLOVER	(1 << 8)
#define PCIE_ERROR_COR_REPLAY_TIMER	(1 << 12)
#define PCIE_ERROR_COR_ADVISORY		(1 << 13)
		     u32 correctable_mask;
		     u32 control;
		     u32 log[4];
		     u32 root_command;
		     u32 root_status; u16 correctable_error_source;
		     u16 error_source;}) pcie_advanced_error_regs_t;
/* *INDENT-ON* */

/* Virtual Channel */
#define PCI_VC_PORT_REG1	4
#define PCI_VC_PORT_REG2	8
#define PCI_VC_PORT_CTRL	12
#define PCI_VC_PORT_STATUS	14
#define PCI_VC_RES_CAP		16
#define PCI_VC_RES_CTRL		20
#define PCI_VC_RES_STATUS	26

/* Power Budgeting */
#define PCI_PWR_DSR		4	/* Data Select Register */
#define PCI_PWR_DATA		8	/* Data Register */
#define PCI_PWR_DATA_BASE(x)	((x) & 0xff)	/* Base Power */
#define PCI_PWR_DATA_SCALE(x)	(((x) >> 8) & 3)	/* Data Scale */
#define PCI_PWR_DATA_PM_SUB(x)	(((x) >> 10) & 7)	/* PM Sub State */
#define PCI_PWR_DATA_PM_STATE(x) (((x) >> 13) & 3)	/* PM State */
#define PCI_PWR_DATA_TYPE(x)	(((x) >> 15) & 7)	/* Type */
#define PCI_PWR_DATA_RAIL(x)	(((x) >> 18) & 7)	/* Power Rail */
#define PCI_PWR_CAP		12	/* Capability */
#define PCI_PWR_CAP_BUDGET(x)	((x) & 1)	/* Included in system budget */

#endif /* included_vlib_pci_config_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
