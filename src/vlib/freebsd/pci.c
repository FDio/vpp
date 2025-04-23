/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Tom Jones <thj@freebsd.org>
 *
 * This software was developed by Tom Jones <thj@freebsd.org> under sponsorship
 * from the FreeBSD Foundation.
 *
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <sys/pciio.h>

#include <fcntl.h>
#include <dirent.h>
#include <net/if.h>

extern vlib_pci_main_t freebsd_pci_main;

uword
vlib_pci_get_private_data (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

void
vlib_pci_set_private_data (vlib_main_t *vm, vlib_pci_dev_handle_t h,
			   uword private_data)
{
}

vlib_pci_addr_t *
vlib_pci_get_addr (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return NULL;
}

u32
vlib_pci_get_numa_node (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

u32
vlib_pci_get_num_msix_interrupts (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t *vm);

vlib_pci_device_info_t *
vlib_pci_get_device_info (vlib_main_t *vm, vlib_pci_addr_t *addr,
			  clib_error_t **error)
{
  /* Populate a vlib_pci_device_info_t from the given address */
  clib_error_t *err = NULL;
  vlib_pci_device_info_t *di = NULL;

  int fd = -1;
  struct pci_conf_io pci;
  struct pci_conf match;
  struct pci_match_conf pattern;
  bzero (&match, sizeof (match));
  bzero (&pattern, sizeof (pattern));

  pattern.pc_sel.pc_domain = addr->domain;
  pattern.pc_sel.pc_bus = addr->bus;
  pattern.pc_sel.pc_dev = addr->slot;
  pattern.pc_sel.pc_func = addr->function;
  pattern.flags = PCI_GETCONF_MATCH_DOMAIN | PCI_GETCONF_MATCH_BUS |
		  PCI_GETCONF_MATCH_DEV | PCI_GETCONF_MATCH_FUNC;

  pci.pat_buf_len = sizeof (pattern);
  pci.num_patterns = 1;
  pci.patterns = &pattern;
  pci.match_buf_len = sizeof (match);
  pci.num_matches = 1;
  pci.matches = &match;
  pci.offset = 0;
  pci.generation = 0;
  pci.status = 0;

  fd = open ("/dev/pci", 0);
  if (fd == -1)
    {
      err = clib_error_return_unix (0, "open '/dev/pci'");
      goto error;
    }

  if (ioctl (fd, PCIOCGETCONF, &pci) == -1)
    {
      err = clib_error_return_unix (0, "reading PCIOCGETCONF");
      goto error;
    }

  di = clib_mem_alloc (sizeof (vlib_pci_device_info_t));
  clib_memset (di, 0, sizeof (vlib_pci_device_info_t));

  di->addr.as_u32 = addr->as_u32;
  di->numa_node = 0; /* TODO: Place holder until we have NUMA on FreeBSD */

  di->device_class = match.pc_class;
  di->vendor_id = match.pc_vendor;
  di->device_id = match.pc_device;
  di->revision = match.pc_revid;

  di->product_name = NULL;
  di->vpd_r = 0;
  di->vpd_w = 0;
  di->driver_name = format (0, "%s", &match.pd_name);
  di->iommu_group = -1;

  goto done;

error:
  vlib_pci_free_device_info (di);
  di = NULL;
done:
  if (error)
    *error = err;
  close (fd);
  return di;
}

clib_error_t *__attribute__ ((weak))
vlib_pci_get_device_root_bus (vlib_pci_addr_t *addr, vlib_pci_addr_t *root_bus)
{
  return NULL;
}

clib_error_t *
vlib_pci_bind_to_uio (vlib_main_t *vm, vlib_pci_addr_t *addr,
		      char *uio_drv_name, int force)
{
  clib_error_t *error = 0;

  if (error)
    {
      return error;
    }

  if (strncmp ("auto", uio_drv_name, 5) == 0)
    {
      /* TODO: We should confirm that nic_uio is loaded and return an error. */
      uio_drv_name = "nic_uio";
    }
  return error;
}

clib_error_t *
vlib_pci_register_intx_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				pci_intx_handler_function_t *intx_handler)
{
  return NULL;
}

clib_error_t *
vlib_pci_unregister_intx_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return NULL;
}

clib_error_t *
vlib_pci_register_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				u32 start, u32 count,
				pci_msix_handler_function_t *msix_handler)
{
  return NULL;
}

clib_error_t *
vlib_pci_unregister_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				  u32 start, u32 count)
{
  return NULL;
}

clib_error_t *
vlib_pci_enable_msix_irq (vlib_main_t *vm, vlib_pci_dev_handle_t h, u16 start,
			  u16 count)
{
  return NULL;
}

uword
vlib_pci_get_msix_file_index (vlib_main_t *vm, vlib_pci_dev_handle_t h,
			      u16 index)
{
  return 0;
}

clib_error_t *
vlib_pci_disable_msix_irq (vlib_main_t *vm, vlib_pci_dev_handle_t h, u16 start,
			   u16 count)
{
  return NULL;
}

/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_main_t *vm, vlib_pci_dev_handle_t h,
			    vlib_read_or_write_t read_or_write, uword address,
			    void *data, u32 n_bytes)
{
  return NULL;
}

clib_error_t *
vlib_pci_map_region (vlib_main_t *vm, vlib_pci_dev_handle_t h, u32 resource,
		     void **result)
{
  return NULL;
}

clib_error_t *
vlib_pci_map_region_fixed (vlib_main_t *vm, vlib_pci_dev_handle_t h,
			   u32 resource, u8 *addr, void **result)
{
  return NULL;
}

clib_error_t *
vlib_pci_io_region (vlib_main_t *vm, vlib_pci_dev_handle_t h, u32 resource)
{
  return NULL;
}

clib_error_t *
vlib_pci_read_write_io (vlib_main_t *vm, vlib_pci_dev_handle_t h,
			vlib_read_or_write_t read_or_write, uword offset,
			void *data, u32 length)
{
  return NULL;
}

clib_error_t *
vlib_pci_map_dma (vlib_main_t *vm, vlib_pci_dev_handle_t h, void *ptr)
{
  return NULL;
}

int
vlib_pci_supports_virtual_addr_dma (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  return 0;
}

clib_error_t *
vlib_pci_device_open (vlib_main_t *vm, vlib_pci_addr_t *addr,
		      pci_device_id_t ids[], vlib_pci_dev_handle_t *handle)
{
  return NULL;
}

void
vlib_pci_device_close (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
}

void
init_device_from_registered (vlib_main_t *vm, vlib_pci_device_info_t *di)
{
}

static int
pci_addr_cmp (void *v1, void *v2)
{
  vlib_pci_addr_t *a1 = v1;
  vlib_pci_addr_t *a2 = v2;

  if (a1->domain > a2->domain)
    return 1;
  if (a1->domain < a2->domain)
    return -1;
  if (a1->bus > a2->bus)
    return 1;
  if (a1->bus < a2->bus)
    return -1;
  if (a1->slot > a2->slot)
    return 1;
  if (a1->slot < a2->slot)
    return -1;
  if (a1->function > a2->function)
    return 1;
  if (a1->function < a2->function)
    return -1;
  return 0;
}

vlib_pci_addr_t *
vlib_pci_get_all_dev_addrs ()
{
  vlib_pci_addr_t *addrs = 0;

  int fd = -1;
  struct pci_conf_io pci;
  struct pci_conf matches[32];
  bzero (matches, sizeof (matches));

  pci.pat_buf_len = 0;
  pci.num_patterns = 0;
  pci.patterns = NULL;
  pci.match_buf_len = sizeof (matches);
  pci.num_matches = 32;
  pci.matches = (struct pci_conf *) &matches;
  pci.offset = 0;
  pci.generation = 0;
  pci.status = 0;

  fd = open ("/dev/pci", 0);
  if (fd == -1)
    {
      clib_error_return_unix (0, "opening /dev/pci");
      return (NULL);
    }

  if (ioctl (fd, PCIOCGETCONF, &pci) == -1)
    {
      clib_error_return_unix (0, "reading pci config");
      close (fd);
      return (NULL);
    }

  for (int i = 0; i < pci.num_matches; i++)
    {
      struct pci_conf *m = &pci.matches[i];
      vlib_pci_addr_t addr;

      addr.domain = m->pc_sel.pc_domain;
      addr.bus = m->pc_sel.pc_bus;
      addr.slot = m->pc_sel.pc_dev;
      addr.function = m->pc_sel.pc_func;

      vec_add1 (addrs, addr);
    }

  vec_sort_with_function (addrs, pci_addr_cmp);
  close (fd);

  return addrs;
}

clib_error_t *
freebsd_pci_init (vlib_main_t *vm)
{
  vlib_pci_main_t *pm = &pci_main;
  vlib_pci_addr_t *addr = 0, *addrs;

  pm->vlib_main = vm;

  ASSERT (sizeof (vlib_pci_addr_t) == sizeof (u32));

  addrs = vlib_pci_get_all_dev_addrs ();
  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      if ((d = vlib_pci_get_device_info (vm, addr, 0)))
	{
	  init_device_from_registered (vm, d);
	  vlib_pci_free_device_info (d);
	}
    }

  return 0;
}

VLIB_INIT_FUNCTION (freebsd_pci_init);
