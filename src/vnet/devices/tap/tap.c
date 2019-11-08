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
#include <net/if_arp.h>
#include <sched.h>
#include <limits.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vlib/physmem.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/netlink.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/tap/tap.h>

tap_main_t tap_main;

#define tap_log_err(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, tap_main.log_default, "tap%u: " f, dev->dev_instance, ## __VA_ARGS__)
#define tap_log_dbg(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, tap_main.log_default, "tap%u: " f, dev->dev_instance, ## __VA_ARGS__)

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      tap_log_err (vif, "%U", format_clib_error, err); \
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

static void
tap_free (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_main_t *mm = &virtio_main;
  tap_main_t *tm = &tap_main;
  int i;

  /* *INDENT-OFF* */
  vec_foreach_index (i, vif->vhost_fds) if (vif->vhost_fds[i] != -1)
    close (vif->vhost_fds[i]);
  vec_foreach_index (i, vif->rxq_vrings)
    virtio_vring_free_rx (vm, vif, RX_QUEUE (i));
  vec_foreach_index (i, vif->txq_vrings)
    virtio_vring_free_tx (vm, vif, TX_QUEUE (i));
  /* *INDENT-ON* */

  if (vif->tap_fd != -1)
    close (vif->tap_fd);

  vec_free (vif->vhost_fds);
  vec_free (vif->rxq_vrings);
  vec_free (vif->txq_vrings);
  vec_free (vif->host_if_name);
  vec_free (vif->net_ns);
  vec_free (vif->host_bridge);
  clib_error_free (vif->error);

  tm->tap_ids = clib_bitmap_set (tm->tap_ids, vif->id, 0);
  clib_memset (vif, 0, sizeof (*vif));
  pool_put (mm->interfaces, vif);
}

void
tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args)
{
  vlib_thread_main_t *thm = vlib_get_thread_main ();
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  tap_main_t *tm = &tap_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int i;
  int old_netns_fd = -1;
  struct ifreq ifr = {.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR };
  size_t hdrsz;
  struct vhost_memory *vhost_mem = 0;
  virtio_if_t *vif = 0;
  clib_error_t *err = 0;
  unsigned int tap_features;
  int tfd, vfd, nfd = -1;
  char *host_if_name = 0;
  unsigned int offload = 0;
  u16 num_q_pairs;

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

  pool_get_zero (vim->interfaces, vif);
  vif->type = VIRTIO_IF_TYPE_TAP;
  vif->dev_instance = vif - vim->interfaces;
  vif->id = args->id;
  vif->num_txqs = thm->n_vlib_mains;
  vif->num_rxqs = args->num_rx_queues;
  num_q_pairs = clib_max (vif->num_rxqs, vif->num_txqs);

  if (ethernet_mac_address_is_zero (args->host_mac_addr))
    ethernet_mac_address_generate (args->host_mac_addr);
  clib_memcpy (vif->host_mac_addr, args->host_mac_addr, 6);

  if ((vif->tap_fd = tfd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return_unix (0, "open '/dev/net/tun'");
      goto error;
    }
  tap_log_dbg (vif, "open tap fd %d", tfd);

  _IOCTL (tfd, TUNGETFEATURES, &tap_features);
  tap_log_dbg (vif, "TUNGETFEATURES: features 0x%lx", tap_features);
  if ((tap_features & IFF_VNET_HDR) == 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return (0, "vhost-net backend not available");
      goto error;
    }

  if ((tap_features & IFF_MULTI_QUEUE) == 0)
    {
      if (args->num_rx_queues > 1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return (0, "multiqueue not supported");
	  goto error;
	}
      vif->num_rxqs = vif->num_txqs = num_q_pairs = 1;
    }
  else
    ifr.ifr_flags |= IFF_MULTI_QUEUE;

  hdrsz = sizeof (struct virtio_net_hdr_v1);
  if (args->tap_flags & TAP_FLAG_GSO)
    {
      offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
      vif->gso_enabled = 1;
    }

  _IOCTL (tfd, TUNSETIFF, (void *) &ifr);
  tap_log_dbg (vif, "TUNSETIFF fd %d name %s flags 0x%x", tfd,
	       ifr.ifr_ifrn.ifrn_name, ifr.ifr_flags);

  vif->ifindex = if_nametoindex (ifr.ifr_ifrn.ifrn_name);
  tap_log_dbg (vif, "ifindex %d", vif->ifindex);

  if (!args->host_if_name)
    host_if_name = ifr.ifr_ifrn.ifrn_name;
  else
    host_if_name = (char *) args->host_if_name;

  fcntl (tfd, F_SETFL, O_NONBLOCK);

  tap_log_dbg (vif, "TUNSETVNETHDRSZ: fd %d vnet_hdr_sz %u", tfd, hdrsz);
  _IOCTL (tfd, TUNSETVNETHDRSZ, &hdrsz);

  i = INT_MAX;
  tap_log_dbg (vif, "TUNSETSNDBUF: fd %d sndbuf %d", tfd, i);
  _IOCTL (tfd, TUNSETSNDBUF, &i);

  tap_log_dbg (vif, "TUNSETOFFLOAD: fd %d offload 0x%lx", tfd, offload);
  _IOCTL (tfd, TUNSETOFFLOAD, offload);

  clib_memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_addr.sa_family = ARPHRD_ETHER;
  clib_memcpy (ifr.ifr_hwaddr.sa_data, vif->host_mac_addr, 6);
  tap_log_dbg (vif, "SIOCSIFHWADDR: fd %d hwaddr %U", tfd,
	       format_hex_bytes, ifr.ifr_hwaddr.sa_data, 6);
  _IOCTL (tfd, SIOCSIFHWADDR, (void *) &ifr);

  /* open vhost-net fd for each queue pair and set ownership */
  for (i = 0; i < num_q_pairs; i++)
    {
      if ((vfd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
	  args->error = clib_error_return_unix (0, "open '/dev/vhost-net'");
	  goto error;
	}
      vec_add1 (vif->vhost_fds, vfd);
      virtio_log_debug (vif, "open vhost-net fd %d qpair %u", vfd, i);
      _IOCTL (vfd, VHOST_SET_OWNER, 0);
      virtio_log_debug (vif, "VHOST_SET_OWNER: fd %u", vfd);
    }

  _IOCTL (vif->vhost_fds[0], VHOST_GET_FEATURES, &vif->remote_features);
  virtio_log_debug (vif, "VHOST_GET_FEATURES: features 0x%lx",
		    vif->remote_features);

  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_NET_F_MRG_RXBUF feature");
      goto error;
    }

  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) ==
      0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_RING_F_INDIRECT_DESC feature");
      goto error;
    }

  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_F_VERSION_1)) == 0)
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      args->error = clib_error_return (0, "vhost-net backend doesn't support "
				       "VIRTIO_F_VERSION_1 features");
      goto error;
    }

  vif->features |= VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF);
  vif->features |= VIRTIO_FEATURE (VIRTIO_F_VERSION_1);
  vif->features |= VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC);

  virtio_set_net_hdr_size (vif);

  /* if namespace is specified, all further netlink messages should be executed
     after we change our net namespace */
  if (args->host_namespace)
    {
      old_netns_fd = open ("/proc/self/ns/net", O_RDONLY);
      if ((nfd = open_netns_fd ((char *) args->host_namespace)) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
	  args->error = clib_error_return_unix (0, "open_netns_fd '%s'",
						args->host_namespace);
	  goto error;
	}
      args->error = vnet_netlink_set_link_netns (vif->ifindex, nfd,
						 host_if_name);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
      if (setns (nfd, CLONE_NEWNET) == -1)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
	  args->error = clib_error_return_unix (0, "setns '%s'",
						args->host_namespace);
	  goto error;
	}
      if ((vif->ifindex = if_nametoindex (host_if_name)) == 0)
	{
	  args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
	  args->error = clib_error_return_unix (0, "if_nametoindex '%s'",
						host_if_name);
	  goto error;
	}
    }
  else
    {
      if (host_if_name)
	{
	  args->error = vnet_netlink_set_link_name (vif->ifindex,
						    host_if_name);
	  if (args->error)
	    {
	      args->rv = VNET_API_ERROR_NETLINK_ERROR;
	      goto error;
	    }
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

  if (args->host_mtu_set)
    {
      args->error =
	vnet_netlink_set_link_mtu (vif->ifindex, args->host_mtu_size);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }
  else if (tm->host_mtu_size != 0)
    {
      args->error =
	vnet_netlink_set_link_mtu (vif->ifindex, tm->host_mtu_size);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
      args->host_mtu_set = 1;
      args->host_mtu_size = tm->host_mtu_size;
    }

  for (i = 0; i < num_q_pairs; i++)
    {
      if (i < vif->num_rxqs && (args->error =
				virtio_vring_init (vm, vif, RX_QUEUE (i),
						   args->rx_ring_sz)))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  goto error;
	}

      if (i < vif->num_txqs && (args->error =
				virtio_vring_init (vm, vif, TX_QUEUE (i),
						   args->tx_ring_sz)))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  goto error;
	}
    }

  /* setup features and memtable */
  i = sizeof (struct vhost_memory) + sizeof (struct vhost_memory_region);
  vhost_mem = clib_mem_alloc (i);
  clib_memset (vhost_mem, 0, i);
  vhost_mem->nregions = 1;
  vhost_mem->regions[0].memory_size = vpm->max_size;
  vhost_mem->regions[0].guest_phys_addr = vpm->base_addr;
  vhost_mem->regions[0].userspace_addr =
    vhost_mem->regions[0].guest_phys_addr;

  for (i = 0; i < vhost_mem->nregions; i++)
    virtio_log_debug (vif, "memtable region %u memory_size 0x%lx "
		      "guest_phys_addr 0x%lx userspace_addr 0x%lx", i,
		      vhost_mem->regions[0].memory_size,
		      vhost_mem->regions[0].guest_phys_addr,
		      vhost_mem->regions[0].userspace_addr);


  for (i = 0; i < num_q_pairs; i++)
    {
      int fd = vif->vhost_fds[i];
      _IOCTL (fd, VHOST_SET_FEATURES, &vif->features);
      virtio_log_debug (vif, "VHOST_SET_FEATURES: fd %u features 0x%lx",
			fd, vif->features);
      _IOCTL (fd, VHOST_SET_MEM_TABLE, vhost_mem);
      virtio_log_debug (vif, "VHOST_SET_MEM_TABLE: fd %u", fd);
    }

  /* finish initializing queue pair */
  for (i = 0; i < num_q_pairs * 2; i++)
    {
      struct vhost_vring_addr addr = { 0 };
      struct vhost_vring_state state = { 0 };
      struct vhost_vring_file file = { 0 };
      virtio_vring_t *vring;
      u16 qp = i >> 1;
      int fd = vif->vhost_fds[qp];

      if (i & 1)
	{
	  if (qp >= vif->num_txqs)
	    continue;
	  vring = vec_elt_at_index (vif->txq_vrings, qp);
	}
      else
	{
	  if (qp >= vif->num_rxqs)
	    continue;
	  vring = vec_elt_at_index (vif->rxq_vrings, qp);
	}

      addr.index = state.index = file.index = vring->queue_id & 1;
      state.num = vring->size;
      virtio_log_debug (vif, "VHOST_SET_VRING_NUM fd %d index %u num %u", fd,
			state.index, state.num);
      _IOCTL (fd, VHOST_SET_VRING_NUM, &state);

      addr.flags = 0;
      addr.desc_user_addr = pointer_to_uword (vring->desc);
      addr.avail_user_addr = pointer_to_uword (vring->avail);
      addr.used_user_addr = pointer_to_uword (vring->used);

      virtio_log_debug (vif, "VHOST_SET_VRING_ADDR fd %d index %u flags 0x%x "
			"desc_user_addr 0x%lx avail_user_addr 0x%lx "
			"used_user_addr 0x%lx", fd, addr.index,
			addr.flags, addr.desc_user_addr, addr.avail_user_addr,
			addr.used_user_addr);
      _IOCTL (fd, VHOST_SET_VRING_ADDR, &addr);

      file.fd = vring->call_fd;
      virtio_log_debug (vif, "VHOST_SET_VRING_CALL fd %d index %u call_fd %d",
			fd, file.index, file.fd);
      _IOCTL (fd, VHOST_SET_VRING_CALL, &file);

      file.fd = vring->kick_fd;
      virtio_log_debug (vif, "VHOST_SET_VRING_KICK fd %d index %u kick_fd %d",
			fd, file.index, file.fd);
      _IOCTL (fd, VHOST_SET_VRING_KICK, &file);

      file.fd = tfd;
      virtio_log_debug (vif, "VHOST_NET_SET_BACKEND fd %d index %u tap_fd %d",
			fd, file.index, file.fd);
      _IOCTL (fd, VHOST_NET_SET_BACKEND, &file);
    }

  if (!args->mac_addr_set)
    ethernet_mac_address_generate (args->mac_addr);

  clib_memcpy (vif->mac_addr, args->mac_addr, 6);

  vif->host_if_name = format (0, "%s%c", host_if_name, 0);
  vif->net_ns = format (0, "%s%c", args->host_namespace, 0);
  vif->host_bridge = format (0, "%s%c", args->host_bridge, 0);
  vif->host_mtu_size = args->host_mtu_size;
  vif->host_ip4_prefix_len = args->host_ip4_prefix_len;
  vif->host_ip6_prefix_len = args->host_ip6_prefix_len;
  if (args->host_ip4_prefix_len)
    clib_memcpy (&vif->host_ip4_addr, &args->host_ip4_addr, 4);
  if (args->host_ip6_prefix_len)
    clib_memcpy (&vif->host_ip6_addr, &args->host_ip6_addr, 16);

  args->error = ethernet_register_interface (vnm, virtio_device_class.index,
					     vif->dev_instance,
					     vif->mac_addr,
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
  args->rv = 0;
  hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  if (args->tap_flags & TAP_FLAG_GSO)
    {
      hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
      vnm->interface_main.gso_interface_count++;
    }
  vnet_hw_interface_set_input_node (vnm, vif->hw_if_index,
				    virtio_input_node.index);

  for (i = 0; i < vif->num_rxqs; i++)
    {
      vnet_hw_interface_assign_rx_thread (vnm, vif->hw_if_index, i, ~0);
      vnet_hw_interface_set_rx_mode (vnm, vif->hw_if_index, i,
				     VNET_HW_INTERFACE_RX_MODE_DEFAULT);
    }

  vif->per_interface_next_index = ~0;
  virtio_vring_set_numa_node (vm, vif, RX_QUEUE (0));
  vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
  vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  vif->cxq_vring = NULL;

  goto done;

error:
  if (err)
    {
      ASSERT (args->error == 0);
      args->error = err;
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
    }

  tap_free (vm, vif);
done:
  if (vhost_mem)
    clib_mem_free (vhost_mem);
  if (old_netns_fd != -1)
    close (old_netns_fd);
  if (nfd != -1)
    close (nfd);
}

int
tap_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  int i;
  virtio_if_t *vif;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  if (vif->type != VIRTIO_IF_TYPE_TAP)
    return VNET_API_ERROR_INVALID_INTERFACE;

  /* decrement if this was a GSO interface */
  if (hw->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO)
    vnm->interface_main.gso_interface_count--;

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, vif->sw_if_index, 0);
  for (i = 0; i < vif->num_rxqs; i++)
    vnet_hw_interface_unassign_rx_thread (vnm, vif->hw_if_index, i);

  ethernet_delete_interface (vnm, vif->hw_if_index);
  vif->hw_if_index = ~0;

  tap_free (vm, vif);

  return 0;
}

int
tap_gso_enable_disable (vlib_main_t * vm, u32 sw_if_index, int enable_disable)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif;
  vnet_hw_interface_t *hw;
  clib_error_t *err = 0;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);

  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  const unsigned int gso_on = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
  const unsigned int gso_off = 0;
  unsigned int offload = enable_disable ? gso_on : gso_off;
  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);
  vif->gso_enabled = enable_disable ? 1 : 0;
  if (enable_disable)
    {
      if ((hw->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO) == 0)
	{
	  vnm->interface_main.gso_interface_count++;
	  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
	}
    }
  else
    {
      if ((hw->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO) != 0)
	{
	  vnm->interface_main.gso_interface_count--;
	  hw->flags &= ~VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
	}
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
  virtio_vring_t *vring;
  vnet_hw_interface_t *hi;
  tap_interface_details_t *r_tapids = NULL;
  tap_interface_details_t *tapid = NULL;

  /* *INDENT-OFF* */
  pool_foreach (vif, mm->interfaces,
    if (vif->type != VIRTIO_IF_TYPE_TAP)
      continue;
    vec_add2(r_tapids, tapid, 1);
    clib_memset (tapid, 0, sizeof (*tapid));
    tapid->id = vif->id;
    tapid->sw_if_index = vif->sw_if_index;
    hi = vnet_get_hw_interface (vnm, vif->hw_if_index);
    clib_memcpy(tapid->dev_name, hi->name,
                MIN (ARRAY_LEN (tapid->dev_name) - 1,
                     strlen ((const char *) hi->name)));
    vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS(0));
    tapid->rx_ring_sz = vring->size;
    vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS(0));
    tapid->tx_ring_sz = vring->size;
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
    tapid->host_mtu_size = vif->host_mtu_size;
  );
  /* *INDENT-ON* */

  *out_tapids = r_tapids;

  return 0;
}

static clib_error_t *
tap_mtu_config (vlib_main_t * vm, unformat_input_t * input)
{
  tap_main_t *tm = &tap_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "host-mtu %d", &tm->host_mtu_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

/* tap { host-mtu <size> } configuration. */
VLIB_CONFIG_FUNCTION (tap_mtu_config, "tap");

static clib_error_t *
tap_init (vlib_main_t * vm)
{
  tap_main_t *tm = &tap_main;
  clib_error_t *error = 0;

  tm->log_default = vlib_log_register_class ("tap", 0);
  vlib_log_debug (tm->log_default, "initialized");

  tm->host_mtu_size = 0;

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
