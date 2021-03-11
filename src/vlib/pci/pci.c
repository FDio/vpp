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
 * pci.c: Linux user space PCI bus management.
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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

vlib_pci_main_t pci_main;

vlib_pci_device_info_t * __attribute__ ((weak))
vlib_pci_get_device_info (vlib_main_t * vm, vlib_pci_addr_t * addr,
			  clib_error_t ** error)
{
  if (error)
    *error = clib_error_return (0, "unsupported");
  return 0;
}

vlib_pci_addr_t * __attribute__ ((weak)) vlib_pci_get_all_dev_addrs ()
{
  return 0;
}

static clib_error_t *
show_pci_fn (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_pci_addr_t *addr = 0, *addrs;
  int show_all = 0;
  u8 *s = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	show_all = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  vlib_cli_output (vm, "%-13s%-5s%-12s%-14s%-16s%-32s%s",
		   "Address", "Sock", "VID:PID", "Link Speed", "Driver",
		   "Product Name", "Vital Product Data");

  addrs = vlib_pci_get_all_dev_addrs ();

  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      d = vlib_pci_get_device_info (vm, addr, 0);

      if (!d)
        continue;

      if (d->device_class != PCI_CLASS_NETWORK_ETHERNET && !show_all)
	continue;

      vec_reset_length (s);
      if (d->numa_node >= 0)
	s = format (s, "  %d", d->numa_node);

      vlib_cli_output (
	vm, "%-13U%-5v%04x:%04x   %-14U%-16s%-32v%U", format_vlib_pci_addr,
	addr, s, d->vendor_id, d->device_id, format_vlib_pci_link_speed, d,
	d->driver_name ? (char *) d->driver_name : "", d->product_name,
	format_vlib_pci_vpd, d->vpd_r, (u8 *) 0);
      vlib_pci_free_device_info (d);
    }

  vec_free (s);
  vec_free (addrs);
  return 0;
}

uword
unformat_vlib_pci_addr (unformat_input_t * input, va_list * args)
{
  vlib_pci_addr_t *addr = va_arg (*args, vlib_pci_addr_t *);
  u32 x[4];

  if (!unformat (input, "%x:%x:%x.%x", &x[0], &x[1], &x[2], &x[3]))
    return 0;

  addr->domain = x[0];
  addr->bus = x[1];
  addr->slot = x[2];
  addr->function = x[3];

  return 1;
}

u8 *
format_vlib_pci_addr (u8 * s, va_list * va)
{
  vlib_pci_addr_t *addr = va_arg (*va, vlib_pci_addr_t *);
  return format (s, "%04x:%02x:%02x.%x", addr->domain, addr->bus,
		 addr->slot, addr->function);
}

u8 *
format_vlib_pci_link_speed (u8 * s, va_list * va)
{
  vlib_pci_device_info_t *d = va_arg (*va, vlib_pci_device_info_t *);
  pcie_config_regs_t *r =
    pci_config_find_capability (&d->config0, PCI_CAP_ID_PCIE);
  int width;

  if (!r)
    return format (s, "unknown");

  width = (r->link_status >> 4) & 0x3f;

  if ((r->link_status & 0xf) == 1)
    return format (s, "2.5 GT/s x%u", width);
  if ((r->link_status & 0xf) == 2)
    return format (s, "5.0 GT/s x%u", width);
  if ((r->link_status & 0xf) == 3)
    return format (s, "8.0 GT/s x%u", width);
  if ((r->link_status & 0xf) == 4)
    return format (s, "16.0 GT/s x%u", width);
  return format (s, "unknown");
}

u8 *
format_vlib_pci_vpd (u8 * s, va_list * args)
{
  u8 *data = va_arg (*args, u8 *);
  u8 *id = va_arg (*args, u8 *);
  u32 indent = format_get_indent (s);
  char *string_types[] = { "PN", "EC", "SN", "MN", 0 };
  uword p = 0;
  int first_line = 1;

  if (vec_len (data) < 3)
    return s;

  while (p + 3 < vec_len (data))
    {

      if (data[p] == 0 && data[p + 1] == 0)
	return s;

      if (p + data[p + 2] > vec_len (data))
	return s;

      if (id == 0)
	{
	  int is_string = 0;
	  char **c = string_types;

	  while (c[0])
	    {
	      if (*(u16 *) & data[p] == *(u16 *) c[0])
		is_string = 1;
	      c++;
	    }

	  if (data[p + 2])
	    {
	      if (!first_line)
		s = format (s, "\n%U", format_white_space, indent);
	      else
		{
		  first_line = 0;
		  s = format (s, " ");
		}

	      s = format (s, "%c%c: ", data[p], data[p + 1]);
	      if (is_string)
		vec_add (s, data + p + 3, data[p + 2]);
	      else
		{
		  int i;
		  const int max_bytes = 8;
		  s = format (s, "0x");
		  for (i = 0; i < clib_min (data[p + 2], max_bytes); i++)
		    s = format (s, " %02x", data[p + 3 + i]);

		  if (data[p + 2] > max_bytes)
		    s = format (s, " ...");
		}
	    }
	}
      else if (*(u16 *) & data[p] == *(u16 *) id)
	{
	  vec_add (s, data + p + 3, data[p + 2]);
	  return s;
	}

      p += 3 + data[p + 2];
    }

  return s;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pci_command, static) = {
  .path = "show pci",
  .short_help = "show pci [all]",
  .function = show_pci_fn,
};
/* *INDENT-ON* */

clib_error_t *
pci_bus_init (vlib_main_t * vm)
{
  vlib_pci_main_t *pm = &pci_main;
  pm->log_default = vlib_log_register_class ("pci", 0);
  return 0;
}

VLIB_INIT_FUNCTION (pci_bus_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
