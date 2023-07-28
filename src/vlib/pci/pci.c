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

VLIB_REGISTER_LOG_CLASS (pci_log, static) = {
  .class_name = "pci",
};

#define log_debug(h, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, pci_log.class, "%U: " f,                    \
	    format_vlib_pci_log, h, ##__VA_ARGS__)

u8 *
format_vlib_pci_log (u8 *s, va_list *va)
{
  vlib_pci_dev_handle_t h = va_arg (*va, vlib_pci_dev_handle_t);
  return format (s, "%U", format_vlib_pci_addr,
		 vlib_pci_get_addr (vlib_get_main (), h));
}

vlib_pci_device_info_t *__attribute__ ((weak))
vlib_pci_get_device_info (vlib_main_t *vm, vlib_pci_addr_t *addr,
			  clib_error_t **error)
{
  if (error)
    *error = clib_error_return (0, "unsupported");
  return 0;
}

clib_error_t *__attribute__ ((weak))
vlib_pci_get_device_root_bus (vlib_pci_addr_t *addr, vlib_pci_addr_t *root_bus)
{
  return 0;
}

vlib_pci_addr_t * __attribute__ ((weak)) vlib_pci_get_all_dev_addrs ()
{
  return 0;
}

static clib_error_t *
_vlib_pci_config_set_control_bit (vlib_main_t *vm, vlib_pci_dev_handle_t h,
				  u16 bit, int new_val, int *already_set)
{
  u16 control, old;
  clib_error_t *err;

  err = vlib_pci_read_write_config (
    vm, h, VLIB_READ, STRUCT_OFFSET_OF (vlib_pci_config_t, command), &old,
    STRUCT_SIZE_OF (vlib_pci_config_t, command));

  if (err)
    return err;

  control = new_val ? old | bit : old & ~bit;
  *already_set = old == control;
  if (*already_set)
    return 0;

  return vlib_pci_read_write_config (
    vm, h, VLIB_WRITE, STRUCT_OFFSET_OF (vlib_pci_config_t, command), &control,
    STRUCT_SIZE_OF (vlib_pci_config_t, command));
}

clib_error_t *
vlib_pci_intr_enable (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  const vlib_pci_config_reg_command_t cmd = { .intx_disable = 1 };
  clib_error_t *err;
  int already_set;

  err = _vlib_pci_config_set_control_bit (vm, h, cmd.as_u16, 0, &already_set);
  log_debug (h, "interrupt%senabled", already_set ? " " : " already ");
  return err;
}

clib_error_t *
vlib_pci_intr_disable (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  const vlib_pci_config_reg_command_t cmd = { .intx_disable = 1 };
  clib_error_t *err;
  int already_set;

  err = _vlib_pci_config_set_control_bit (vm, h, cmd.as_u16, 1, &already_set);
  log_debug (h, "interrupt%sdisabled", already_set ? " " : " already ");
  return err;
}

clib_error_t *
vlib_pci_bus_master_enable (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  const vlib_pci_config_reg_command_t cmd = { .bus_master = 1 };
  clib_error_t *err;
  int already_set;

  err = _vlib_pci_config_set_control_bit (vm, h, cmd.as_u16, 1, &already_set);
  log_debug (h, "bus-master%senabled", already_set ? " " : " already ");
  return err;
}

clib_error_t *
vlib_pci_bus_master_disable (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  const vlib_pci_config_reg_command_t cmd = { .bus_master = 1 };
  clib_error_t *err;
  int already_set;

  err = _vlib_pci_config_set_control_bit (vm, h, cmd.as_u16, 0, &already_set);
  log_debug (h, "bus-master%sdisabled", already_set ? " " : " already ");
  return err;
}

clib_error_t *
vlib_pci_function_level_reset (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  vlib_pci_config_t cfg;
  pci_capability_pcie_t *cap;
  pci_capability_pcie_dev_control_t dev_control;
  clib_error_t *err;
  u8 offset;

  log_debug (h, "function level reset");

  err = vlib_pci_read_write_config (vm, h, VLIB_READ, 0, &cfg, sizeof (cfg));
  if (err)
    return err;

  offset = cfg.cap_ptr;

  while (offset)
    {
      cap = (pci_capability_pcie_t *) (cfg.data + offset);

      if (cap->capability_id == PCI_CAP_ID_PCIE)
	break;

      offset = cap->next_offset;
    }

  if (cap->capability_id != PCI_CAP_ID_PCIE)
    return clib_error_return (0, "PCIe capability config not found");

  if (cap->dev_caps.flr_capable == 0)
    return clib_error_return (0, "PCIe function level reset not supported");

  dev_control = cap->dev_control;
  dev_control.function_level_reset = 1;

  if ((err = vlib_pci_write_config_u16 (
	 vm, h, offset + STRUCT_OFFSET_OF (pci_capability_pcie_t, dev_control),
	 &dev_control.as_u16)))
    return err;

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
format_vlib_pci_link_port (u8 *s, va_list *va)
{
  vlib_pci_config_t *c = va_arg (*va, vlib_pci_config_t *);
  pci_capability_pcie_t *r = pci_config_find_capability (c, PCI_CAP_ID_PCIE);

  if (!r)
    return format (s, "unknown");

  return format (s, "P%d", r->link_caps.port_number);
}

static u8 *
_vlib_pci_link_speed (u8 *s, u8 speed, u8 width)
{
  static char *speeds[] = {
    [1] = "2.5", [2] = "5.0", [3] = "8.0", [4] = "16.0", [5] = "32.0"
  };

  if (speed > ARRAY_LEN (speeds) || speeds[speed] == 0)
    s = format (s, "unknown speed");
  else
    s = format (s, "%s GT/s", speeds[speed]);

  return format (s, " x%u", width);
}

u8 *
format_vlib_pci_link_speed (u8 *s, va_list *va)
{
  vlib_pci_config_t *c = va_arg (*va, vlib_pci_config_t *);
  pci_capability_pcie_t *r = pci_config_find_capability (c, PCI_CAP_ID_PCIE);

  if (!r)
    return format (s, "unknown");

  return _vlib_pci_link_speed (s, r->link_status.link_speed,
			       r->link_status.negotiated_link_width);
}

u8 *
format_vlib_pci_link_speed_cap (u8 *s, va_list *va)
{
  vlib_pci_config_t *c = va_arg (*va, vlib_pci_config_t *);
  pci_capability_pcie_t *r = pci_config_find_capability (c, PCI_CAP_ID_PCIE);

  if (!r)
    return format (s, "unknown");

  return _vlib_pci_link_speed (s, r->link_caps.max_link_speed,
			       r->link_caps.max_link_width);
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

VLIB_CLI_COMMAND (show_pci_command, static) = {
  .path = "show pci",
  .short_help = "show pci [all]",
  .function = show_pci_fn,
};

