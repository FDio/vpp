/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>
#include <sched.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/netlink.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/tap/tap.h>

tap_main_t tap_main;

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      goto error; \
    }

static u32
virtio_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			u32 flags)
{
  /* nothing for now */
  //TODO On MTU change call vnet_netlink_set_if_mtu
  return 0;
}

static int
open_netns_fd (char *netns)
{
  u8 *s = 0;
  int fd;

  if (strncmp (netns, "pid:", 4) == 0)
    s = format (0, "/proc/%u/ns/net%c", atoi (netns + 4), 0);
  else if (netns[0] == '/')
    s = format (0, "%s%c", netns, 0);
  else
    s = format (0, "/var/run/netns/%s%c", netns, 0);

  fd = open ((char *) s, O_RDONLY);
  vec_free (s);
  return fd;
}

#define TAP_MAX_INSTANCE 1024

void
tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *thm = vlib_get_thread_main ();
  virtio_main_t *vim = &virtio_main;
  tap_main_t *tm = &tap_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int i;
  int old_netns_fd = -1;
  struct ifreq ifr;
  size_t hdrsz;
  struct vhost_memory *vhost_mem = 0;
  virtio_if_t *vif = 0;
  clib_error_t *err = 0;

  if (args->id != ~0)
    {
      if (clib_bitmap_get (tm->tap_ids, args->id))
	{
	  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
	  args->error = clib_error_return (0, "interface already exists");
	  return;
	}
    }
  else
    {
      args->id = clib_bitmap_first_clear (tm->tap_ids);
    }

  if (args->id > TAP_MAX_INSTANCE)
    {
      args->rv = VNET_API_ERROR_UNSPECIFIED;
      args->error = clib_error_return (0, "cannot find free interface id");
      return;
    }

  clib_memset (&ifr, 0, sizeof (ifr));
  pool_get (vim->interfaces, vif);
  vif->dev_instance = vif - vim->interfaces;
  vif->tap_fd = -1;
  vif->id = args->id;

  if ((vif->fd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return_unix (0, "open '/dev/vhost-net'");
      goto error;
    }

  _IOCTL (vif->fd, VHOST_GET_FEATURES, &vif->remote_features);

  if ((vif->remote_features & (1ULL << VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_NET_F_MRG_RXBUF feature");
      goto error;
    }

  if ((vif->remote_features & (1ULL << VIRTIO_RING_F_INDIRECT_DESC)) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_RING_F_INDIRECT_DESC feature");
      goto error;
    }

  if ((vif->remote_features & (1ULL << VIRTIO_F_VERSION_1)) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_F_VERSION_1 features");
      goto error;
    }

  vif->features |= 1ULL << VIRTIO_NET_F_MRG_RXBUF;
  vif->features |= 1ULL << VIRTIO_F_VERSION_1;
  vif->features |= 1ULL << VIRTIO_RING_F_INDIRECT_DESC;

  _IOCTL (vif->fd, VHOST_SET_FEATURES, &vif->features);

  if ((vif->tap_fd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return_unix (0, "open '/dev/net/tun'");
      goto error;
    }

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR;
  _IOCTL (vif->tap_fd, TUNSETIFF, (void *) &ifr);
  vif->ifindex = if_nametoindex (ifr.ifr_ifrn.ifrn_name);

  unsigned int offload = 0;
  hdrsz = sizeof (struct virtio_net_hdr_v1);
  if (args->gso_enable)
    {
      offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;
      vif->gso_enabled = 1;

    }
  else
    {
      vif->gso_enabled = 0;
    }

  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);

  _IOCTL (vif->tap_fd, TUNSETVNETHDRSZ, &hdrsz);
  _IOCTL (vif->fd, VHOST_SET_OWNER, 0);

  /* if namespace is specified, all further netlink messages should be excuted
     after we change our net namespace */
  if (args->host_namespace)
    {
      int fd;
      old_netns_fd = open ("/proc/self/ns/net", O_RDONLY);
      if ((fd = open_netns_fd ((char *) args->host_namespace)) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return_unix (0, "open_netns_fd '%s'",
						args->host_namespace);
	  goto error;
	}
      args->error = vnet_netlink_set_link_netns (vif->ifindex, fd,
						 (char *) args->host_if_name);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
      if (setns (fd, CLONE_NEWNET) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
	  args->error = clib_error_return_unix (0, "setns '%s'",
						args->host_namespace);
	  goto error;
	}
      close (fd);
      if ((vif->ifindex = if_nametoindex ((char *) args->host_if_name)) == 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
	  args->error = clib_error_return_unix (0, "if_nametoindex '%s'",
						args->host_if_name);
	  goto error;
	}
    }
  else
    {
      if (args->host_if_name)
	{
	  args->error = vnet_netlink_set_link_name (vif->ifindex,
						    (char *)
						    args->host_if_name);
	  if (args->error)
	    {
	      args->rv = VNET_API_ERROR_NETLINK_ERROR;
	      goto error;
	    }
	}
    }

  if (!ethernet_mac_address_is_zero (args->host_mac_addr))
    {
      args->error = vnet_netlink_set_link_addr (vif->ifindex,
						args->host_mac_addr);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_bridge)
    {
      args->error = vnet_netlink_set_link_master (vif->ifindex,
						  (char *) args->host_bridge);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }


  if (args->host_ip4_prefix_len)
    {
      args->error = vnet_netlink_add_ip4_addr (vif->ifindex,
					       &args->host_ip4_addr,
					       args->host_ip4_prefix_len);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_ip6_prefix_len)
    {
      args->error = vnet_netlink_add_ip6_addr (vif->ifindex,
					       &args->host_ip6_addr,
					       args->host_ip6_prefix_len);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  args->error = vnet_netlink_set_link_state (vif->ifindex, 1 /* UP */ );
  if (args->error)
    {
      args->rv = VNET_API_ERROR_NETLINK_ERROR;
      goto error;
    }

  if (args->host_ip4_gw_set)
    {
      args->error = vnet_netlink_add_ip4_route (0, 0, &args->host_ip4_gw);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_ip6_gw_set)
    {
      args->error = vnet_netlink_add_ip6_route (0, 0, &args->host_ip6_gw);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  /* switch back to old net namespace */
  if (args->host_namespace)
    {
      if (setns (old_netns_fd, CLONE_NEWNET) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return_unix (0, "setns '%s'",
						args->host_namespace);
	  goto error;
	}
    }

  /* Set vhost memory table */
  i = sizeof (struct vhost_memory) + sizeof (struct vhost_memory_region);
  vhost_mem = clib_mem_alloc (i);
  clib_memset (vhost_mem, 0, i);
  vhost_mem->nregions = 1;
  vhost_mem->regions[0].memory_size = (1ULL << 47) - 4096;
  _IOCTL (vif->fd, VHOST_SET_MEM_TABLE, vhost_mem);

  if ((args->error = virtio_vring_init (vm, vif, 0, args->rx_ring_sz)))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      goto error;
    }

  if ((args->error = virtio_vring_init (vm, vif, 1, args->tx_ring_sz)))
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      goto error;
    }

  if (!args->mac_addr_set)
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (args->mac_addr + 2, &rnd, sizeof (rnd));
      args->mac_addr[0] = 2;
      args->mac_addr[1] = 0xfe;
    }
  vif->rx_ring_sz = args->rx_ring_sz != 0 ? args->rx_ring_sz : 256;
  vif->tx_ring_sz = args->tx_ring_sz != 0 ? args->tx_ring_sz : 256;
  vif->host_if_name = args->host_if_name;
  args->host_if_name = 0;
  vif->net_ns = args->host_namespace;
  args->host_namespace = 0;
  vif->host_bridge = args->host_bridge;
  args->host_bridge = 0;
  clib_memcpy (vif->host_mac_addr, args->host_mac_addr, 6);
  vif->host_ip4_prefix_len = args->host_ip4_prefix_len;
  vif->host_ip6_prefix_len = args->host_ip6_prefix_len;
  if (args->host_ip4_prefix_len)
    clib_memcpy (&vif->host_ip4_addr, &args->host_ip4_addr, 4);
  if (args->host_ip6_prefix_len)
    clib_memcpy (&vif->host_ip6_addr, &args->host_ip6_addr, 16);

  args->error = ethernet_register_interface (vnm, virtio_device_class.index,
					     vif->dev_instance,
					     args->mac_addr,
					     &vif->hw_if_index,
					     virtio_eth_flag_change);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  tm->tap_ids = clib_bitmap_set (tm->tap_ids, vif->id, 1);
  sw = vnet_get_hw_sw_interface (vnm, vif->hw_if_index);
  vif->sw_if_index = sw->sw_if_index;
  args->sw_if_index = vif->sw_if_index;
  hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  if (args->gso_enable)
    hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
  vnet_hw_interface_set_input_node (vnm, vif->hw_if_index,
				    virtio_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vif->hw_if_index, 0, ~0);
  vnet_hw_interface_set_rx_mode (vnm, vif->hw_if_index, 0,
				 VNET_HW_INTERFACE_RX_MODE_DEFAULT);
  vif->per_interface_next_index = ~0;
  vif->type = VIRTIO_IF_TYPE_TAP;
  vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
  vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  if (thm->n_vlib_mains > 1)
    clib_spinlock_init (&vif->lockp);
  goto done;

error:
  if (err)
    {
      ASSERT (args->error == 0);
      args->error = err;
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
    }
  if (vif->tap_fd != -1)
    close (vif->tap_fd);
  if (vif->fd != -1)
    close (vif->fd);
  vec_foreach_index (i, vif->vrings) virtio_vring_free (vm, vif, i);
  vec_free (vif->vrings);
  clib_memset (vif, 0, sizeof (virtio_if_t));
  pool_put (vim->interfaces, vif);

done:
  if (vhost_mem)
    clib_mem_free (vhost_mem);
  if (old_netns_fd != -1)
    close (old_netns_fd);
}

int
tap_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  tap_main_t *tm = &tap_main;
  int i;
  virtio_if_t *vif;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, vif->sw_if_index, 0);
  vnet_hw_interface_unassign_rx_thread (vnm, vif->hw_if_index, 0);

  ethernet_delete_interface (vnm, vif->hw_if_index);
  vif->hw_if_index = ~0;

  if (vif->tap_fd != -1)
    close (vif->tap_fd);
  if (vif->fd != -1)
    close (vif->fd);

  vec_foreach_index (i, vif->vrings) virtio_vring_free (vm, vif, i);
  vec_free (vif->vrings);

  tm->tap_ids = clib_bitmap_set (tm->tap_ids, vif->id, 0);
  clib_spinlock_free (&vif->lockp);
  clib_memset (vif, 0, sizeof (*vif));
  pool_put (mm->interfaces, vif);

  return 0;
}

int
tap_gso_enable_disable (vlib_main_t * vm, u32 sw_if_index, int enable_disable)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif;
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  clib_error_t *err = 0;

  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  const unsigned int gso_on =
    TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;
  const unsigned int gso_off = 0;
  unsigned int offload = enable_disable ? gso_on : gso_off;
  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);
  vif->gso_enabled = enable_disable ? 1 : 0;
  if (enable_disable)
    {
      hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
    }
  else
    {
      hw->flags &= ~VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
    }

error:
  if (err)
    {
      clib_warning ("Error %s gso on sw_if_index %d",
		    enable_disable ? "enabling" : "disabling", sw_if_index);
      return VNET_API_ERROR_SYSCALL_ERROR_3;
    }
  return 0;
}

int
tap_dump_ifs (tap_interface_details_t ** out_tapids)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif;
  vnet_hw_interface_t *hi;
  tap_interface_details_t *r_tapids = NULL;
  tap_interface_details_t *tapid = NULL;

  /* *INDENT-OFF* */
  pool_foreach (vif, mm->interfaces,
    vec_add2(r_tapids, tapid, 1);
    clib_memset (tapid, 0, sizeof (*tapid));
    tapid->id = vif->id;
    tapid->sw_if_index = vif->sw_if_index;
    hi = vnet_get_hw_interface (vnm, vif->hw_if_index);
    clib_memcpy(tapid->dev_name, hi->name,
                MIN (ARRAY_LEN (tapid->dev_name) - 1,
                     strlen ((const char *) hi->name)));
    tapid->rx_ring_sz = vif->rx_ring_sz;
    tapid->tx_ring_sz = vif->tx_ring_sz;
    clib_memcpy(tapid->host_mac_addr, vif->host_mac_addr, 6);
    if (vif->host_if_name)
      {
        clib_memcpy(tapid->host_if_name, vif->host_if_name,
                    MIN (ARRAY_LEN (tapid->host_if_name) - 1,
                    strlen ((const char *) vif->host_if_name)));
      }
    if (vif->net_ns)
      {
        clib_memcpy(tapid->host_namespace, vif->net_ns,
                    MIN (ARRAY_LEN (tapid->host_namespace) - 1,
                    strlen ((const char *) vif->net_ns)));
      }
    if (vif->host_bridge)
      {
        clib_memcpy(tapid->host_bridge, vif->host_bridge,
                    MIN (ARRAY_LEN (tapid->host_bridge) - 1,
                    strlen ((const char *) vif->host_bridge)));
      }
    if (vif->host_ip4_prefix_len)
      clib_memcpy(tapid->host_ip4_addr, &vif->host_ip4_addr, 4);
    tapid->host_ip4_prefix_len = vif->host_ip4_prefix_len;
    if (vif->host_ip6_prefix_len)
      clib_memcpy(tapid->host_ip6_addr, &vif->host_ip6_addr, 16);
    tapid->host_ip6_prefix_len = vif->host_ip6_prefix_len;
  );
  /* *INDENT-ON* */

  *out_tapids = r_tapids;

  return 0;
}

static clib_error_t *
tap_init (vlib_main_t * vm)
{
  tap_main_t *tm = &tap_main;
  clib_error_t *error = 0;

  tm->log_default = vlib_log_register_class ("tap", 0);
  vlib_log_debug (tm->log_default, "initialized");

  return error;
}

VLIB_INIT_FUNCTION (tap_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
