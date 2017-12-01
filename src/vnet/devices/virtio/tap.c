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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/netlink.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/tap.h>

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

void
tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int i, fd;
  struct ifreq ifr;
  size_t hdrsz;
  struct vhost_memory *vhost_mem = 0;
  virtio_if_t *vif = 0;
  clib_error_t *err = 0;

  memset (&ifr, 0, sizeof (ifr));
  pool_get (vim->interfaces, vif);
  vif->dev_instance = vif - vim->interfaces;
  vif->tap_fd = -1;

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
  strncpy (ifr.ifr_ifrn.ifrn_name, (char *) args->name, IF_NAMESIZE - 1);
  _IOCTL (vif->tap_fd, TUNSETIFF, (void *) &ifr);

  vif->ifindex = if_nametoindex ((char *) args->name);

  unsigned int offload = 0;
  hdrsz = sizeof (struct virtio_net_hdr_v1);
  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);
  _IOCTL (vif->tap_fd, TUNSETVNETHDRSZ, &hdrsz);
  _IOCTL (vif->fd, VHOST_SET_OWNER, 0);

  if (args->host_bridge)
    {
      int master_ifindex = if_nametoindex ((char *) args->host_bridge);
      args->error = vnet_netlink_set_if_master (vif->ifindex, master_ifindex);
      if (args->error)
	{
	  args->rv = VNET_API_ERROR_NETLINK_ERROR;
	  goto error;
	}
    }

  if (args->host_namespace)
    {
      args->error = vnet_netlink_set_if_namespace (vif->ifindex,
						   (char *)
						   args->host_namespace);
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

  /* Set vhost memory table */
  i = sizeof (struct vhost_memory) + sizeof (struct vhost_memory_region);
  vhost_mem = clib_mem_alloc (i);
  memset (vhost_mem, 0, i);
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

  /* set host side up */
  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) > 0)
    {
      memset (&ifr, 0, sizeof (struct ifreq));
      strncpy (ifr.ifr_name, (char *) args->name, sizeof (ifr.ifr_name) - 1);
      _IOCTL (fd, SIOCGIFFLAGS, (void *) &ifr);
      ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
      _IOCTL (fd, SIOCSIFFLAGS, (void *) &ifr);
      close (fd);
    }

  if (!args->hw_addr_set)
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (args->hw_addr + 2, &rnd, sizeof (rnd));
      args->hw_addr[0] = 2;
      args->hw_addr[1] = 0xfe;
    }
  vif->name = args->name;
  args->name = 0;
  vif->net_ns = args->host_namespace;
  args->host_namespace = 0;
  args->error = ethernet_register_interface (vnm, virtio_device_class.index,
					     vif->dev_instance, args->hw_addr,
					     &vif->hw_if_index,
					     virtio_eth_flag_change);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, vif->hw_if_index);
  vif->sw_if_index = sw->sw_if_index;
  args->sw_if_index = vif->sw_if_index;
  hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
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
  vec_foreach_index (i, vif->vrings) virtio_vring_free (vif, i);
  memset (vif, 0, sizeof (virtio_if_t));
  pool_put (vim->interfaces, vif);

done:
  if (vhost_mem)
    clib_mem_free (vhost_mem);
}

int
tap_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
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

  ethernet_delete_interface (vnm, vif->hw_if_index);
  vif->hw_if_index = ~0;

  if (vif->tap_fd != -1)
    close (vif->tap_fd);
  if (vif->fd != -1)
    close (vif->fd);

  vec_foreach_index (i, vif->vrings) virtio_vring_free (vif, i);
  vec_free (vif->vrings);

  memset (vif, 0, sizeof (*vif));
  pool_put (mm->interfaces, vif);

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
    memset (tapid, 0, sizeof (*tapid));
    tapid->sw_if_index = vif->sw_if_index;
    hi = vnet_get_hw_interface (vnm, vif->hw_if_index);
    clib_memcpy(tapid->dev_name, hi->name,
		MIN (ARRAY_LEN (tapid->dev_name) - 1,
		     strlen ((const char *) hi->name)));
  );
  /* *INDENT-ON* */

  *out_tapids = r_tapids;

  return 0;
}

static clib_error_t *
tap_init (vlib_main_t * vm)
{

  return 0;
}

VLIB_INIT_FUNCTION (tap_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
