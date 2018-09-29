/*
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tap_inject.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <vnet/unix/tuntap.h>

#include <vlib/unix/unix.h>


static clib_error_t *
tap_inject_tap_read (clib_file_t * f)
{
  vlib_main_t * vm = vlib_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_add1 (im->rx_file_descriptors, f->file_descriptor);

  vlib_node_set_interrupt_pending (vm, im->rx_node_index);

  return 0;
}

#define TAP_INJECT_TAP_BASE_NAME "vpp"

clib_error_t *
tap_inject_tap_connect (vnet_hw_interface_t * hw)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnet_main, hw->hw_if_index);
  static const int one = 1;
  int fd;
  struct ifreq ifr;
  clib_file_t template;
  u32 tap_fd;
  u8 * name;

  memset (&ifr, 0, sizeof (ifr));
  memset (&template, 0, sizeof (template));

  ASSERT (hw->hw_if_index == sw->sw_if_index);

  /* Create the tap. */
  tap_fd = open ("/dev/net/tun", O_RDWR);

  if ((int)tap_fd < 0)
    return clib_error_return (0, "failed to open tun device");

  name = format (0, TAP_INJECT_TAP_BASE_NAME "%u%c", hw->hw_instance, 0);

  strncpy (ifr.ifr_name, (char *) name, sizeof (ifr.ifr_name) - 1);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  if (ioctl (tap_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
      close (tap_fd);
      return clib_error_return (0, "failed to create tap");
    }

  if (ioctl (tap_fd, FIONBIO, &one) < 0)
    {
      close (tap_fd);
      return clib_error_return (0, "failed to set tap to non-blocking io");
    }

  /* Open a socket to configure the device. */
  fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

  if (fd < 0)
    {
      close (tap_fd);
      return clib_error_return (0, "failed to configure tap");
    }

  if (hw->hw_address)
    clib_memcpy (ifr.ifr_hwaddr.sa_data, hw->hw_address, ETHER_ADDR_LEN);

  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  /* Set the hardware address. */
  if (ioctl (fd, SIOCSIFHWADDR, &ifr) < 0)
    {
      close (tap_fd);
      close (fd);
      return clib_error_return (0, "failed to set tap hardware address");
    }

  /* Get the tap if index. */
  if (ioctl (fd, SIOCGIFINDEX, &ifr) < 0)
    {
      close (tap_fd);
      close (fd);
      return clib_error_return (0, "failed to procure tap if index");
    }

  close (fd);

  /* Get notified when the tap needs to be read. */
  template.read_function = tap_inject_tap_read;
  template.file_descriptor = tap_fd;

  clib_file_add (&file_main, &template);

  tap_inject_insert_tap (sw->sw_if_index, tap_fd, ifr.ifr_ifindex);

  return 0;
}

clib_error_t *
tap_inject_tap_disconnect (u32 sw_if_index)
{
  u32 tap_fd;

  tap_fd = tap_inject_lookup_tap_fd (sw_if_index);
  if (tap_fd == ~0)
    return clib_error_return (0, "failed to disconnect tap");

  tap_inject_delete_tap (sw_if_index);

  close (tap_fd);
  return 0;
}


u8 *
format_tap_inject_tap_name (u8 * s, va_list * args)
{
  int fd;
  struct ifreq ifr;

  fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

  if (fd < 0)
    return 0;

  memset (&ifr, 0, sizeof (ifr));

  ifr.ifr_ifindex = va_arg (*args, u32);

  if (ioctl (fd, SIOCGIFNAME, &ifr) < 0)
    {
      close (fd);
      return 0;
    }

  close (fd);

  return format (s, "%s", ifr.ifr_name);
}
