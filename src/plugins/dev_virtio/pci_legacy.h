/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_virtio_pci_legacy_h__
#define __included_virtio_pci_legacy_h__

/*
 * VirtIO Header, located in BAR 0.
 */
#define VIRTIO_PCI_HOST_FEATURES  0	/* host's supported features (32bit, RO) */
#define VIRTIO_PCI_GUEST_FEATURES 4	/* guest's supported features (32, RW) */
#define VIRTIO_PCI_QUEUE_PFN      8	/* physical address of VQ (32, RW) */
#define VIRTIO_PCI_QUEUE_NUM      12	/* number of ring entries (16, RO) */
#define VIRTIO_PCI_QUEUE_SEL      14	/* current VQ selection (16, RW) */
#define VIRTIO_PCI_QUEUE_NOTIFY   16	/* notify host regarding VQ (16, RW) */
#define VIRTIO_PCI_STATUS         18	/* device status register (8, RW) */
#define VIRTIO_PCI_ISR            19	/* interrupt status register, reading
					 * also clears the register (8, RO) */
/* Only if MSIX is enabled: */
#define VIRTIO_MSI_CONFIG_VECTOR  20	/* configuration change vector (16, RW) */
#define VIRTIO_MSI_QUEUE_VECTOR   22	/* vector for selected VQ notifications
					   (16, RW) */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12

#endif /* __included_virtio_pci_legacy_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
