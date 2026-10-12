/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 WITH Linux-syscall-note */
#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define KDI_DEVICE_NAME_LEN	64
#define KDI_RESOURCE_NAME_LEN	64
#define KDI_CONTROL_DEVICE_NAME "vpp-kdi"
#define KDI_DEVICE_PATH		"/dev/" KDI_CONTROL_DEVICE_NAME

enum kdi_resource_kind
{
  KDI_RESOURCE_CLOCK,
  KDI_RESOURCE_RESET,
  KDI_RESOURCE_INTERCONNECT,
  KDI_RESOURCE_PHY,
};

/* Resource open */
struct kdi_resource_open
{
  enum kdi_resource_kind type;
  char device_name[KDI_DEVICE_NAME_LEN];
  char node_name[KDI_RESOURCE_NAME_LEN];
  char resource_name[KDI_RESOURCE_NAME_LEN];
};

#define KDI_IOC_MAGIC	      'K'
#define KDI_IOC_OPEN_RESOURCE _IOW (KDI_IOC_MAGIC, 0, struct kdi_resource_open)

/* Clock operations */
#define KDI_IOC_CLOCK_ENABLE   _IO (KDI_IOC_MAGIC, 1)
#define KDI_IOC_CLOCK_DISABLE  _IO (KDI_IOC_MAGIC, 2)
#define KDI_IOC_CLOCK_SET_RATE _IOW (KDI_IOC_MAGIC, 3, __u64)

/* Reset operations */
#define KDI_IOC_RESET_ASSERT   _IO (KDI_IOC_MAGIC, 4)
#define KDI_IOC_RESET_DEASSERT _IO (KDI_IOC_MAGIC, 5)
#define KDI_IOC_RESET_PULSE    _IO (KDI_IOC_MAGIC, 6)

/* Interconnect operations */
struct kdi_interconnect_op
{
  __aligned_u64 average_bw;
  __aligned_u64 peak_bw;
};

#define KDI_IOC_INTERCONNECT_SET_BW _IOW (KDI_IOC_MAGIC, 7, struct kdi_interconnect_op)

/* PHY operations */
#define KDI_IOC_PHY_POWER_ON  _IO (KDI_IOC_MAGIC, 8)
#define KDI_IOC_PHY_POWER_OFF _IO (KDI_IOC_MAGIC, 9)
