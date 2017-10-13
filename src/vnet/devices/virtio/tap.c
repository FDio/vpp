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
  return 0;
}


clib_error_t *
clib_netlink_set_if_attr (int ifindex, unsigned short rta_type, void *data,
			  int data_len)
{
  clib_error_t *err = 0;
  int sock;
  struct sockaddr_nl ra = { 0 };
  struct
  {
    struct nlmsghdr nh;
    struct ifinfomsg ifmsg;
    char attrbuf[512];
  } req;
  struct rtattr *rta;

  memset (&req, 0, sizeof (req));
  if ((sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    {
      err = clib_error_return_unix (0, "socket(AF_NETLINK)");
      goto error;
    }

  ra.nl_family = AF_NETLINK;
  ra.nl_pid = getpid ();

  if ((bind (sock, (struct sockaddr *) &ra, sizeof (ra))) == -1)
    return clib_error_return_unix (0, "bind");

  req.nh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifinfomsg));
  req.nh.nlmsg_flags = NLM_F_REQUEST;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.ifmsg.ifi_family = AF_UNSPEC;
  req.ifmsg.ifi_index = ifindex;
  req.ifmsg.ifi_change = 0xffffffff;
  rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN (req.nh.nlmsg_len));
  rta->rta_type = rta_type;
  rta->rta_len = RTA_LENGTH (data_len);
  req.nh.nlmsg_len = NLMSG_ALIGN (req.nh.nlmsg_len) + RTA_LENGTH (data_len);
  memcpy (RTA_DATA (rta), data, data_len);

  if ((send (sock, &req, req.nh.nlmsg_len, 0)) == -1)
    err = clib_error_return_unix (0, "send");

error:
  return err;
}

clib_error_t *
clib_netlink_set_if_mtu (int ifindex, int mtu)
{
  clib_error_t *err;

  err = clib_netlink_set_if_attr (ifindex, IFLA_MTU, &mtu, sizeof (int));
  return err;
}

clib_error_t *
clib_netlink_set_if_namespace (int ifindex, char *net_ns)
{
  clib_error_t *err;
  int ns_fd;
  u8 *s;
  s = format (0, "/var/run/netns/%s%c", net_ns, 0);
  ns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);
  if (ns_fd == -1)
    return clib_error_return (0, "namespace '%s' doesn't exist", net_ns);

  err =
    clib_netlink_set_if_attr (ifindex, IFLA_NET_NS_FD, &ns_fd, sizeof (int));
  close (ns_fd);
  return err;
}

int
tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int i;
  clib_error_t *err = 0;
  struct ifreq ifr;
  size_t hdrsz;
  struct vhost_memory *vhost_mem = 0;
  virtio_if_t *vif = 0;
  int rv = 0;

  memset (&ifr, 0, sizeof (ifr));
  pool_get (vim->interfaces, vif);
  vif->dev_instance = vif - vim->interfaces;
  vif->tap_fd = -1;

  if ((vif->fd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  _IOCTL (vif->fd, VHOST_GET_FEATURES, &vif->remote_features);

  if ((vif->remote_features & (1ULL << VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto error;
    }

  if ((vif->remote_features & (1ULL << VIRTIO_RING_F_INDIRECT_DESC)) == 0)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto error;
    }

  if ((vif->remote_features & (1ULL << VIRTIO_F_VERSION_1)) == 0)
    {
      rv = VNET_API_ERROR_UNSUPPORTED;
      goto error;
    }

  vif->features |= 1ULL << VIRTIO_NET_F_MRG_RXBUF;
  vif->features |= 1ULL << VIRTIO_F_VERSION_1;
  vif->features |= 1ULL << VIRTIO_RING_F_INDIRECT_DESC;

  _IOCTL (vif->fd, VHOST_SET_FEATURES, &vif->features);

  if ((vif->tap_fd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR;
  strncpy (ifr.ifr_ifrn.ifrn_name, (char *) args->name, IF_NAMESIZE);
  _IOCTL (vif->tap_fd, TUNSETIFF, (void *) &ifr);

  vif->ifindex = if_nametoindex ((char *) args->name);

  unsigned int offload = 0;
  hdrsz = sizeof (struct virtio_net_hdr_v1);
  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);
  _IOCTL (vif->tap_fd, TUNSETVNETHDRSZ, &hdrsz);
  _IOCTL (vif->fd, VHOST_SET_OWNER, 0);

  if (args->net_ns)
    {
      err = clib_netlink_set_if_namespace (vif->ifindex,
					   (char *) args->net_ns);
      if (err)
	{
	  rv = VNET_API_ERROR_NAMESPACE_CREATE;
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

  if ((err = virtio_vring_init (vm, vif, 0, args->rx_ring_sz)))
    {
      rv = VNET_API_ERROR_VIRTIO_INIT;
      goto error;
    }

  if ((err = virtio_vring_init (vm, vif, 1, args->tx_ring_sz)))
    {
      rv = VNET_API_ERROR_VIRTIO_INIT;
      goto error;
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
  vif->net_ns = args->net_ns;
  args->net_ns = 0;
  err = ethernet_register_interface (vnm, virtio_device_class.index,
				     vif->dev_instance, args->hw_addr,
				     &vif->hw_if_index,
				     virtio_eth_flag_change);
  if (err)
    rv = VNET_API_ERROR_INVALID_REGISTRATION;

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

  return rv;
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
