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

typedef union
{
  struct
  {
    u16 io_space : 1;
    u16 mem_space : 1;
    u16 bus_master : 1;
    u16 special_cycles : 1;
    u16 mem_write_invalidate : 1;
    u16 vga_palette_snoop : 1;
    u16 parity_err_resp : 1;
    u16 _reserved_7 : 1;
    u16 serr_enable : 1;
    u16 fast_b2b_enable : 1;
    u16 intx_disable : 1;
    u16 _reserved_11 : 5;
  };
  u16 as_u16;
} vlib_pci_config_reg_command_t;

typedef union
{
  struct
  {
    u16 _reserved_0 : 3;
    u16 intx_status : 1;
    u16 capabilities_list : 1;
    u16 capaable_66mhz : 1;
    u16 _reserved_6 : 1;
    u16 fast_b2b_capable : 1;
    u16 master_data_parity_error : 1;
    u16 devsel_timing : 2;
    u16 sig_target_abort : 1;
    u16 rec_target_abort : 1;
    u16 rec_master_abort : 1;
    u16 sig_system_err : 1;
    u16 detected_parity_err : 1;
  };
  u16 as_u16;
} vlib_pci_config_reg_status_t;

typedef enum
{
  PCI_HEADER_TYPE_NORMAL = 0,
  PCI_HEADER_TYPE_BRIDGE = 1,
  PCI_HEADER_TYPE_CARDBUS = 2
} __clib_packed pci_config_header_type_t;

#define foreach_pci_config_reg                                                \
  _ (u16, vendor_id)                                                          \
  _ (u16, device_id)                                                          \
  _ (vlib_pci_config_reg_command_t, command)                                  \
  _ (vlib_pci_config_reg_status_t, status)                                    \
  _ (u8, revision_id)                                                         \
  _ (u8, prog_if)                                                             \
  _ (u8, subclass)                                                            \
  _ (u8, class)                                                               \
  _ (u8, cache_line_size)                                                     \
  _ (u8, latency_timer)                                                       \
  _ (pci_config_header_type_t, header_type)                                   \
  _ (u8, bist)                                                                \
  _ (u32, bar, [6])                                                           \
  _ (u32, cardbus_cis_ptr)                                                    \
  _ (u16, sub_vendor_id)                                                      \
  _ (u16, sub_device_id)                                                      \
  _ (u32, exp_rom_base_addr)                                                  \
  _ (u8, cap_ptr)                                                             \
  _ (u8, _reserved_0x35, [3])                                                 \
  _ (u32, _reserved_0x38)                                                     \
  _ (u8, intr_line)                                                           \
  _ (u8, intr_pin)                                                            \
  _ (u8, min_grant)                                                           \
  _ (u8, max_latency)

typedef struct
{
#define _(a, b, ...) a b __VA_ARGS__;
  foreach_pci_config_reg
#undef _
} vlib_pci_config_mandatory_t;

STATIC_ASSERT_SIZEOF (vlib_pci_config_mandatory_t, 64);

typedef union
{
  struct
  {
#define _(a, b, ...) a b __VA_ARGS__;
    foreach_pci_config_reg
#undef _
  };
  u8 data[256];
} vlib_pci_config_t;

STATIC_ASSERT_SIZEOF (vlib_pci_config_t, 256);

typedef union
{
  struct
  {
#define _(a, b, ...) a b __VA_ARGS__;
    foreach_pci_config_reg
#undef _
  };
  u8 data[4096];
} vlib_pci_config_ext_t;

STATIC_ASSERT_SIZEOF (vlib_pci_config_ext_t, 4096);

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
typedef struct
{
  enum pci_capability_type type:8;
  u8 next_offset;
} __clib_packed pci_capability_regs_t;

always_inline void *
pci_config_find_capability (vlib_pci_config_t *t, int cap_type)
{
  pci_capability_regs_t *c;
  u32 next_offset;
  u32 ttl = 48;

  if (!(t->status.capabilities_list))
    return 0;

  next_offset = t->cap_ptr;
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
typedef struct
{
  pci_capability_regs_t header;
  u16 capabilities;
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
  u8 data;
} __clib_packed pci_power_management_regs_t;

/* AGP registers */
typedef struct
{
  pci_capability_regs_t header;
  u8 version;
  u8 rest_of_capability_flags;
  u32 status;
  u32 command;
  /* Command & status common bits. */
#define PCI_AGP_RQ_MASK	0xff000000	/* Maximum number of requests - 1 */
#define PCI_AGP_SBA	0x0200	/* Sideband addressing supported */
#define PCI_AGP_64BIT	0x0020	/* 64-bit addressing supported */
#define PCI_AGP_ALLOW_TRANSACTIONS 0x0100	/* Allow processing of AGP transactions */
#define PCI_AGP_FW	0x0010	/* FW transfers supported/forced */
#define PCI_AGP_RATE4	0x0004	/* 4x transfer rate supported */
#define PCI_AGP_RATE2	0x0002	/* 2x transfer rate supported */
#define PCI_AGP_RATE1	0x0001	/* 1x transfer rate supported */
} __clib_packed pci_agp_regs_t;

/* Vital Product Data */
typedef struct
{
  pci_capability_regs_t header;
  u16 address;
#define PCI_VPD_ADDR_MASK	0x7fff	/* Address mask */
#define PCI_VPD_ADDR_F		0x8000	/* Write 0, 1 indicates completion */
  u32 data;
} __clib_packed pci_vpd_regs_t;

/* Slot Identification */
typedef struct
{
  pci_capability_regs_t header;
  u8 esr;
#define PCI_SID_ESR_NSLOTS	0x1f	/* Number of expansion slots available */
#define PCI_SID_ESR_FIC	0x20	/* First In Chassis Flag */
  u8 chassis;
} __clib_packed pci_sid_regs_t;

/* Message Signalled Interrupts registers */
typedef struct
{
  pci_capability_regs_t header;
  u16 flags;
#define PCI_MSI_FLAGS_ENABLE	(1 << 0)	/* MSI feature enabled */
#define PCI_MSI_FLAGS_GET_MAX_QUEUE_SIZE(x) ((x >> 1) & 0x7)
#define PCI_MSI_FLAGS_MAX_QUEUE_SIZE(x)     (((x) & 0x7) << 1)
#define PCI_MSI_FLAGS_GET_QUEUE_SIZE(x) ((x >> 4) & 0x7)
#define PCI_MSI_FLAGS_QUEUE_SIZE(x)     (((x) & 0x7) << 4)
#define PCI_MSI_FLAGS_64BIT	(1 << 7)	/* 64-bit addresses allowed */
#define PCI_MSI_FLAGS_MASKBIT	(1 << 8)	/* 64-bit mask bits allowed */
  u32 address;
  u32 data;
  u32 mask_bits;
} __clib_packed pci_msi32_regs_t;

typedef struct
{
  pci_capability_regs_t header;
  u16 flags;
  u32 address[2];
  u32 data;
  u32 mask_bits;
} __clib_packed pci_msi64_regs_t;

/* CompactPCI Hotswap Register */
typedef struct
{
  pci_capability_regs_t header;
  u16 control_status;
#define PCI_CHSWP_DHA		0x01	/* Device Hiding Arm */
#define PCI_CHSWP_EIM		0x02	/* ENUM# Signal Mask */
#define PCI_CHSWP_PIE		0x04	/* Pending Insert or Extract */
#define PCI_CHSWP_LOO		0x08	/* LED On / Off */
#define PCI_CHSWP_PI		0x30	/* Programming Interface */
#define PCI_CHSWP_EXT		0x40	/* ENUM# status - extraction */
#define PCI_CHSWP_INS		0x80	/* ENUM# status - insertion */
} __clib_packed pci_chswp_regs_t;

/* PCIX registers */
typedef struct
{
  pci_capability_regs_t header;
  u16 command;
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
} __clib_packed pcix_config_regs_t;

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

/* PCI express extended capabilities. */
typedef enum pcie_capability_type
{
  PCIE_CAP_ADVANCED_ERROR = 1,
  PCIE_CAP_VC = 2,
  PCIE_CAP_DSN = 3,
  PCIE_CAP_PWR = 4,
} pcie_capability_type_t;

/* Common header for capabilities. */
typedef struct
{
  enum pcie_capability_type type:16;
  u16 version:4;
  u16 next_capability:12;
} __clib_packed pcie_capability_regs_t;

typedef struct
{
  pcie_capability_regs_t header;
  u32 uncorrectable_status;
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
  u32 uncorrectable_severity;
  u32 correctable_status;
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
  u32 root_status;
  u16 correctable_error_source;
  u16 error_source;
} __clib_packed pcie_advanced_error_regs_t;

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

#define pci_capability_pcie_dev_caps_t_fields                                 \
  _ (3, max_payload_sz)                                                       \
  _ (2, phantom_fn_present)                                                   \
  _ (1, ext_tags_supported)                                                   \
  _ (3, acceptable_l0s_latency)                                               \
  _ (3, acceptable_l1_latency)                                                \
  _ (1, attention_button_present)                                             \
  _ (1, attention_indicator_present)                                          \
  _ (1, power_indicator_present)                                              \
  _ (1, role_based_error_reporting_supported)                                 \
  _ (2, _reserved_16)                                                         \
  _ (8, slot_ppower_limit_val)                                                \
  _ (2, slot_power_limit_scale)                                               \
  _ (1, flr_capable)                                                          \
  _ (3, _reserved_29)

#define pci_capability_pcie_dev_control_t_fields                              \
  _ (1, enable_correctable_error_reporting)                                   \
  _ (1, enable_non_fatal_error_reporting)                                     \
  _ (1, enable_fatal_error_reporting)                                         \
  _ (1, enable_unsupported_request_reporting)                                 \
  _ (1, enable_relaxed_ordering)                                              \
  _ (3, maximum_payload_size)                                                 \
  _ (1, extended_tag_field_enable)                                            \
  _ (1, phantom_fn_denable)                                                   \
  _ (1, aux_power_pm_enable)                                                  \
  _ (1, enable_no_snoop)                                                      \
  _ (3, max_read_request_size)                                                \
  _ (1, function_level_reset)

#define pci_capability_pcie_dev_status_t_fields                               \
  _ (1, correctable_err_detected)                                             \
  _ (1, non_fatal_err_detected)                                               \
  _ (1, fatal_err_detected)                                                   \
  _ (1, unsupported_request_detected)                                         \
  _ (1, aux_power_detected)                                                   \
  _ (1, transaction_pending)                                                  \
  _ (10, _reserved_6)

#define pci_capability_pcie_link_caps_t_fields                                \
  _ (4, max_link_speed)                                                       \
  _ (5, max_link_width)                                                       \
  _ (2, aspm_support)                                                         \
  _ (3, l0s_exit_latency)                                                     \
  _ (3, l1_exit_latency)                                                      \
  _ (1, clock_power_mgmt_status)                                              \
  _ (1, surprise_down_error_reporting_capable_status)                         \
  _ (1, data_link_layer_link_active_reporting_capable_status)                 \
  _ (1, link_bandwidth_notification_capability_status)                        \
  _ (1, aspm_optionality_compliance)                                          \
  _ (1, _reserved_23)                                                         \
  _ (8, port_number)

#define pci_capability_pcie_link_control_t_fields                             \
  _ (2, aspm_control)                                                         \
  _ (1, _reserved_2)                                                          \
  _ (1, read_completion_boundary)                                             \
  _ (1, link_disable)                                                         \
  _ (1, retrain_clock)                                                        \
  _ (1, common_clock_config)                                                  \
  _ (1, extended_synch)                                                       \
  _ (1, enable_clock_pwr_mgmt)                                                \
  _ (1, hw_autonomous_width_disable)                                          \
  _ (1, link_bw_mgmt_intr_enable)                                             \
  _ (1, link_autonomous_bw_intr_enable)                                       \
  _ (4, _reserved_12)

#define pci_capability_pcie_link_status_t_fields                              \
  _ (4, link_speed)                                                           \
  _ (6, negotiated_link_width)                                                \
  _ (1, _reserved_10)                                                         \
  _ (1, link_training)                                                        \
  _ (1, slot_clock_config)                                                    \
  _ (1, data_link_layer_link_active)                                          \
  _ (1, link_bw_mgmt_status)                                                  \
  _ (1, _reserved_15)

#define pci_capability_pcie_dev_caps2_t_fields                                \
  _ (4, compl_timeout_ranges_supported)                                       \
  _ (1, compl_timeout_disable_supported)                                      \
  _ (1, ari_forwarding_supported)                                             \
  _ (1, atomic_op_routing_supported)                                          \
  _ (1, bit32_atomic_op_completer_supported)                                  \
  _ (1, bit64_atomic_op_completer_supported)                                  \
  _ (1, bit128_cas_completer_supported)                                       \
  _ (1, no_ro_enabled_pr_pr_passing)                                          \
  _ (1, ltr_mechanism_supported)                                              \
  _ (1, tph_completer_supported)                                              \
  _ (18, _reserved_14)

#define pci_capability_pcie_dev_control2_t_fields                             \
  _ (4, completion_timeout_value)                                             \
  _ (1, completion_timeout_disable)                                           \
  _ (1, ari_forwarding_enable)                                                \
  _ (1, atomic_op_requester_enable)                                           \
  _ (1, atomic_op_egress_blocking)                                            \
  _ (1, ido_request_enable)                                                   \
  _ (1, ido_completion_enable)                                                \
  _ (1, ltr_mechanism_enable)                                                 \
  _ (5, _reserved_11)

#define pci_capability_pcie_link_control2_t_fields                            \
  _ (4, target_link_speed)                                                    \
  _ (1, enter_compliance)                                                     \
  _ (1, hw_autonomous_speed_disable)                                          \
  _ (1, selectable_de_emphasis)                                               \
  _ (3, transmit_margin)                                                      \
  _ (1, enter_modified_compliance)                                            \
  _ (1, compliance_sos)                                                       \
  _ (4, compliance_de_emphasis)

#define pci_capability_pcie_link_status2_t_fields                             \
  _ (1, current_de_emphasis_level)                                            \
  _ (15, _reserved_1)

#define __(t, n)                                                              \
  typedef union                                                               \
  {                                                                           \
    struct                                                                    \
    {                                                                         \
      n##_fields;                                                             \
    };                                                                        \
    t as_##t;                                                                 \
  } n;                                                                        \
  STATIC_ASSERT_SIZEOF (n, sizeof (t))

#define _(b, n) u32 n : b;
__ (u32, pci_capability_pcie_dev_caps_t);
__ (u32, pci_capability_pcie_link_caps_t);
__ (u32, pci_capability_pcie_dev_caps2_t);
#undef _
#define _(b, n) u16 n : b;
__ (u16, pci_capability_pcie_dev_control_t);
__ (u16, pci_capability_pcie_dev_status_t);
__ (u16, pci_capability_pcie_link_control_t);
__ (u16, pci_capability_pcie_link_status_t);
__ (u16, pci_capability_pcie_dev_control2_t);
__ (u16, pci_capability_pcie_link_control2_t);
__ (u16, pci_capability_pcie_link_status2_t);
#undef _
#undef __

typedef struct
{
  u8 capability_id;
  u8 next_offset;
  u16 version_id : 3;
  u16 _reserved_0_19 : 13;
  pci_capability_pcie_dev_caps_t dev_caps;
  pci_capability_pcie_dev_control_t dev_control;
  pci_capability_pcie_dev_status_t dev_status;
  pci_capability_pcie_link_caps_t link_caps;
  pci_capability_pcie_link_control_t link_control;
  pci_capability_pcie_link_status_t link_status;
  u32 _reserved_0x14;
  u16 _reserved_0x18;
  u16 _reserved_0x1a;
  u32 _reserved_0x1c;
  u16 _reserved_0x20;
  u16 _reserved_0x22;
  pci_capability_pcie_dev_caps2_t dev_caps2;
  pci_capability_pcie_dev_control2_t dev_control2;
  u16 _reserved_0x2a;
  u32 _reserved_0x2c;
  pci_capability_pcie_link_control2_t link_control2;
  pci_capability_pcie_link_status2_t link_status2;
  u32 _reserved_0x34;
  u16 _reserved_0x38;
  u16 _reserved_0x3a;
} pci_capability_pcie_t;

STATIC_ASSERT_SIZEOF (pci_capability_pcie_t, 60);

#endif /* included_vlib_pci_config_h */

