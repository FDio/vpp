/*
 * Copyright (c) 2021 Intel and/or its affiliates.
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

#include <perfmon/perfmon.h>
#include <perfmon/intel/uncore.h>
#include <vlib/pci/pci.h>
#include <vppinfra/format.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <math.h>

typedef struct
{
  u8 socket_id;
  u8 sad_id;
  u8 iio_unit_id;
} iio_uncore_sad_t;
typedef u32 index_t;

static const char *procfs_pci_path = "/proc/bus/pci";

#define PCM_INTEL_PCI_VENDOR_ID	       0x8086
#define SNR_ICX_SAD_CONTROL_CFG_OFFSET 0x3F4
#define SNR_ICX_MESH2IIO_MMAP_DID      0x09A2

static const u8 icx_sad_to_pmu_id_mapping[] = { 5, 0, 1, 2, 3, 4 };

static const char *iio_bw_footer_message =
  "* this bundle currently only measures x8 and x16 PCIe devices on Port #0\n"
  "or Port #2. Please see the \"Intel® Xeon® Processor Scalable Memory\n"
  "Family Uncore Performance Monitoring Reference Manual(336274)\"\n"
  "Section 2.4 for more information.";

static u32
get_sad_ctrl_cfg (vlib_pci_addr_t *addr)
{
  int fd = 0;
  u32 value;
  u8 *dev_node_name = format (0, "%s/%02x/%02x.%x", procfs_pci_path, addr->bus,
			      addr->slot, addr->function);

  fd = open ((char *) dev_node_name, O_RDWR);
  if (fd < 0)
    return -1;

  if (pread (fd, &value, sizeof (u32), SNR_ICX_SAD_CONTROL_CFG_OFFSET) <
      sizeof (u32))
    value = -1;

  close (fd);

  return value;
}

static u64
get_bus_to_sad_mappings (vlib_main_t *vm, index_t **ph, iio_uncore_sad_t **pp)
{
  index_t *h = 0;
  iio_uncore_sad_t *p = 0, *e = 0;
  vlib_pci_addr_t *addr = 0, *addrs;

  addrs = vlib_pci_get_all_dev_addrs ();

  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      d = vlib_pci_get_device_info (vm, addr, 0);

      if (!d)
	continue;

      if (d->vendor_id == PCM_INTEL_PCI_VENDOR_ID &&
	  d->device_id == SNR_ICX_MESH2IIO_MMAP_DID)
	{

	  u32 sad_ctrl_cfg = get_sad_ctrl_cfg (addr);
	  if (sad_ctrl_cfg == 0xFFFFFFFF)
	    {
	      vlib_pci_free_device_info (d);
	      continue;
	    }

	  pool_get_zero (p, e);

	  e->socket_id = (sad_ctrl_cfg & 0xf);
	  e->sad_id = (sad_ctrl_cfg >> 4) & 0x7;
	  e->iio_unit_id = icx_sad_to_pmu_id_mapping[e->sad_id];

	  hash_set (h, addr->bus, e - p);
	}

      vlib_pci_free_device_info (d);
    }

  vec_free (addrs);

  *ph = h;
  *pp = p;

  return 0;
}

u8 *
format_stack_socket (u8 *s, va_list *va)
{
  iio_uncore_sad_t *e, *p = va_arg (*va, iio_uncore_sad_t *);
  index_t *h = va_arg (*va, index_t *);
  vlib_pci_addr_t root_bus, *addr = va_arg (*va, vlib_pci_addr_t *);
  clib_error_t *err = vlib_pci_get_device_root_bus (addr, &root_bus);
  if (err)
    {
      clib_error_free (err);
      return s;
    }

  uword *pu = hash_get (h, root_bus.bus);
  if (pu)
    {
      e = pool_elt_at_index (p, (index_t) pu[0]);

      s = format (s, "IIO%u/%u", e->socket_id, e->iio_unit_id);
    }
  else
    {
      s = format (s, "[ERR: hash lookup for bus '%u' failed]", root_bus.bus);
    }
  return s;
}

static clib_error_t *
init_intel_uncore_iio_bw (vlib_main_t *vm, struct perfmon_bundle *b)
{
  index_t *h = 0;
  iio_uncore_sad_t *p = 0;
  vlib_pci_addr_t *addr = 0, *addrs;
  u8 *s = 0;

  get_bus_to_sad_mappings (vm, &h, &p);

  s = format (0, "%-10s%-5s%-13s%-12s%-14s%-16s%s\n", "Stack", "Port",
	      "Address", "VID:PID", "Link Speed", "Driver", "Product Name");

  addrs = vlib_pci_get_all_dev_addrs ();

  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      d = vlib_pci_get_device_info (vm, addr, 0);

      if (!d)
	continue;

      if (d->device_class != PCI_CLASS_NETWORK_ETHERNET)
	continue;

      s = format (
	s, "%-10U%-5U%-13U%04x:%04x   %-14U%-16s%v\n", format_stack_socket, p,
	h, addr, format_vlib_pci_link_port, &d->config, format_vlib_pci_addr,
	addr, d->vendor_id, d->device_id, format_vlib_pci_link_speed, d,
	d->driver_name ? (char *) d->driver_name : "", d->product_name);

      vlib_pci_free_device_info (d);
    }

  b->footer = (char *) format (s, "\n%s", iio_bw_footer_message);

  vec_free (addrs);
  pool_free (p);
  hash_free (h);

  return 0;
}

static u8 *
format_intel_uncore_iio_bw (u8 *s, va_list *args)
{
  perfmon_reading_t *r = va_arg (*args, perfmon_reading_t *);
  int col = va_arg (*args, int);
  f64 tr = r->time_running * 1e-9;
  f64 value = 0;

  switch (col)
    {
    case 0:
      s = format (s, "%9.2f", tr);
      break;
    default:
      if (r->time_running)
	{
	  value = r->value[col - 1] * 4 / tr;

	  if (value > 1.0e6)
	    s = format (s, "%9.0fM", value * 1e-6);
	  else if (value > 1.0e3)
	    s = format (s, "%9.0fK", value * 1e-3);
	  else
	    s = format (s, "%9.0f ", value);
	}

      break;
    }

  return s;
}

/*
 * This bundle is currently only supported and tested on Intel Icelake.
 */
static int
is_icelake ()
{
  return clib_cpu_supports_avx512_bitalg () && !clib_cpu_supports_movdir64b ();
}

static perfmon_cpu_supports_t iio_bw_cpu_supports[] = {
  { is_icelake, PERFMON_BUNDLE_TYPE_SYSTEM }
};

PERFMON_REGISTER_BUNDLE (intel_uncore_iio_bw_pci) = {
  .name = "iio-bandwidth-pci",
  .description = "pci iio memory reads and writes per iio stack *",
  .source = "intel-uncore",
  .events[0] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_OF_CPU_PART0_RD,
  .events[1] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART0_WR,
  .events[2] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART2_RD,
  .events[3] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART2_WR,
  .n_events = 4,
  .cpu_supports = iio_bw_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (iio_bw_cpu_supports),
  .format_fn = format_intel_uncore_iio_bw,
  .init_fn = init_intel_uncore_iio_bw,
  .column_headers = PERFMON_STRINGS ("RunTime", "PCIe Rd/P0", "PCIe Wr/P0",
				     "PCIe Rd/P2", "PCIe Wr/P2")
};

PERFMON_REGISTER_BUNDLE (intel_uncore_iio_bw_cpu) = {
  .name = "iio-bandwidth-cpu",
  .description = "cpu iio memory reads and writes per iio stack *",
  .source = "intel-uncore",
  .events[0] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART0_RD,
  .events[1] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART0_WR,
  .events[2] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART2_RD,
  .events[3] = INTEL_UNCORE_E_IIO_UNC_IIO_DATA_REQ_BY_CPU_PART2_WR,
  .n_events = 4,
  .cpu_supports = iio_bw_cpu_supports,
  .n_cpu_supports = ARRAY_LEN (iio_bw_cpu_supports),
  .format_fn = format_intel_uncore_iio_bw,
  .init_fn = init_intel_uncore_iio_bw,
  .column_headers = PERFMON_STRINGS ("RunTime", "CPU Rd/P0", "CPU Wr/P0",
				     "CPU Rd/P2", "CPU Wr/P2")
};
