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

static clib_error_t *
show_pci_fn (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_pci_main_t *pm = &pci_main;
  vlib_pci_device_t *d;
  pci_config_header_t *c;
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

  vlib_cli_output (vm, "%-13s%-7s%-12s%-15s%-20s%-40s",
		   "Address", "Socket", "VID:PID", "Link Speed", "Driver",
		   "Product Name");

  /* *INDENT-OFF* */
  pool_foreach (d, pm->pci_devs, ({
    c = &d->config0.header;

    if (c->device_class != PCI_CLASS_NETWORK_ETHERNET && !show_all)
      continue;

    vec_reset_length (s);

    if (d->numa_node >= 0)
      s = format (s, "  %d", d->numa_node);

    vlib_cli_output (vm, "%-13U%-7v%04x:%04x   %-15U%-20s%-40v",
		     format_vlib_pci_addr, &d->bus_address, s,
		     c->vendor_id, c->device_id,
		     format_vlib_pci_link_speed, d,
		     d->driver_name ? (char *) d->driver_name : "",
		     d->product_name);
  }));
/* *INDENT-ON* */

  vec_free (s);
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
format_vlib_pci_handle (u8 * s, va_list * va)
{
  vlib_pci_addr_t *addr = va_arg (*va, vlib_pci_addr_t *);
  return format (s, "%x/%x/%x", addr->bus, addr->slot, addr->function);
}

u8 *
format_vlib_pci_link_speed (u8 * s, va_list * va)
{
  vlib_pci_device_t *d = va_arg (*va, vlib_pci_device_t *);
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
  return format (s, "unknown");
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
