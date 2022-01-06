/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
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
 *------------------------------------------------------------------
 */

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/devices/netlink.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>

#include <vnet/devices/af_packet/af_packet.h>

af_packet_main_t af_packet_main;

VNET_HW_INTERFACE_CLASS (af_packet_ip_device_hw_interface_class, static) = {
  .name = "af-packet-ip-device",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

#define AF_PACKET_DEFAULT_TX_FRAMES_PER_BLOCK 1024
#define AF_PACKET_DEFAULT_TX_FRAME_SIZE	      (2048 * 5)
#define AF_PACKET_TX_BLOCK_NR		1

#define AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK 1024
#define AF_PACKET_DEFAULT_RX_FRAME_SIZE	      (2048 * 5)
#define AF_PACKET_RX_BLOCK_NR		1

/*defined in net/if.h but clashes with dpdk headers */
unsigned int if_nametoindex (const char *ifname);

typedef struct tpacket_req tpacket_req_t;

static u32
af_packet_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			   u32 flags)
{
  clib_error_t *error;
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hi->dev_instance);

  if (flags == ETHERNET_INTERFACE_FLAG_MTU)
    {
      error =
	vnet_netlink_set_link_mtu (apif->host_if_index, hi->max_packet_bytes);

      if (error)
	{
	  vlib_log_err (apm->log_class, "netlink failed to change MTU: %U",
			format_clib_error, error);
	  clib_error_free (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}
      else
	apif->host_mtu = hi->max_packet_bytes;
    }

  return 0;
}

static int
af_packet_read_mtu (af_packet_if_t *apif)
{
  af_packet_main_t *apm = &af_packet_main;
  clib_error_t *error;
  error = vnet_netlink_get_link_mtu (apif->host_if_index, &apif->host_mtu);
  if (error)
    {
      vlib_log_err (apm->log_class, "netlink failed to get MTU: %U",
		    format_clib_error, error);
      clib_error_free (error);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  return 0;
}

static clib_error_t *
af_packet_fd_read_ready (clib_file_t * uf)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 idx = uf->private_data;
  af_packet_if_t *apif = pool_elt_at_index (apm->interfaces, idx);

  apm->pending_input_bitmap =
    clib_bitmap_set (apm->pending_input_bitmap, idx, 1);

  /* Schedule the rx node */
  vnet_hw_if_rx_queue_set_int_pending (vnm, apif->queue_index);
  return 0;
}

static int
is_bridge (const u8 * host_if_name)
{
  u8 *s;
  DIR *dir = NULL;

  s = format (0, "/sys/class/net/%s/bridge%c", host_if_name, 0);
  dir = opendir ((char *) s);
  vec_free (s);

  if (dir)
    {
      closedir (dir);
      return 0;
    }

  return -1;
}

static int
create_packet_v2_sock (int host_if_index, tpacket_req_t * rx_req,
		       tpacket_req_t * tx_req, int *fd, u8 ** ring)
{
  af_packet_main_t *apm = &af_packet_main;
  int ret;
  struct sockaddr_ll sll;
  int ver = TPACKET_V2;
  socklen_t req_sz = sizeof (struct tpacket_req);
  u32 ring_sz = rx_req->tp_block_size * rx_req->tp_block_nr +
    tx_req->tp_block_size * tx_req->tp_block_nr;

  if ((*fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to create AF_PACKET socket: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  /* bind before rx ring is cfged so we don't receive packets from other interfaces */
  clib_memset (&sll, 0, sizeof (sll));
  sll.sll_family = PF_PACKET;
  sll.sll_protocol = htons (ETH_P_ALL);
  sll.sll_ifindex = host_if_index;
  if (bind (*fd, (struct sockaddr *) &sll, sizeof (sll)) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to bind rx packet socket: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if (setsockopt (*fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof (ver)) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to set rx packet interface version: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  int opt = 1;
  if (setsockopt (*fd, SOL_PACKET, PACKET_LOSS, &opt, sizeof (opt)) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to set packet tx ring error handling option: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

#if defined(PACKET_QDISC_BYPASS)
  /* Introduced with Linux 3.14 so the ifdef should eventually be removed  */
  if (setsockopt (*fd, SOL_PACKET, PACKET_QDISC_BYPASS, &opt, sizeof (opt)) <
      0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to set qdisc bypass error "
		      "handling option: %s (errno %d)",
		      strerror (errno), errno);
    }
#endif

  if (setsockopt (*fd, SOL_PACKET, PACKET_RX_RING, rx_req, req_sz) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to set packet rx ring options: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if (setsockopt (*fd, SOL_PACKET, PACKET_TX_RING, tx_req, req_sz) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to set packet tx ring options: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  *ring =
    mmap (NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, *fd,
	  0);
  if (*ring == MAP_FAILED)
    {
      vlib_log_debug (apm->log_class, "mmap failure: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  return 0;
error:
  if (*fd >= 0)
    {
      close (*fd);
      *fd = -1;
    }
  return ret;
}

int
af_packet_create_if (af_packet_create_if_arg_t *arg)
{
  af_packet_main_t *apm = &af_packet_main;
  vlib_main_t *vm = vlib_get_main ();
  int ret, fd = -1, fd2 = -1;
  struct tpacket_req *rx_req = 0;
  struct tpacket_req *tx_req = 0;
  struct ifreq ifr;
  u8 *ring = 0;
  af_packet_if_t *apif = 0;
  u8 hw_addr[6];
  vnet_sw_interface_t *sw;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_main_t *vnm = vnet_get_main ();
  uword *p;
  uword if_index;
  u8 *host_if_name_dup = 0;
  int host_if_index = -1;
  u32 rx_frames_per_block, tx_frames_per_block;
  u32 rx_frame_size, tx_frame_size;

  p = mhash_get (&apm->if_index_by_host_if_name, arg->host_if_name);
  if (p)
    {
      apif = vec_elt_at_index (apm->interfaces, p[0]);
      arg->sw_if_index = apif->sw_if_index;
      return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  host_if_name_dup = vec_dup (arg->host_if_name);

  rx_frames_per_block = arg->rx_frames_per_block ?
			  arg->rx_frames_per_block :
			  AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK;
  tx_frames_per_block = arg->tx_frames_per_block ?
			  arg->tx_frames_per_block :
			  AF_PACKET_DEFAULT_TX_FRAMES_PER_BLOCK;
  rx_frame_size =
    arg->rx_frame_size ? arg->rx_frame_size : AF_PACKET_DEFAULT_RX_FRAME_SIZE;
  tx_frame_size =
    arg->tx_frame_size ? arg->tx_frame_size : AF_PACKET_DEFAULT_TX_FRAME_SIZE;

  vec_validate (rx_req, 0);
  rx_req->tp_block_size = rx_frame_size * rx_frames_per_block;
  rx_req->tp_frame_size = rx_frame_size;
  rx_req->tp_block_nr = AF_PACKET_RX_BLOCK_NR;
  rx_req->tp_frame_nr = AF_PACKET_RX_BLOCK_NR * rx_frames_per_block;

  vec_validate (tx_req, 0);
  tx_req->tp_block_size = tx_frame_size * tx_frames_per_block;
  tx_req->tp_frame_size = tx_frame_size;
  tx_req->tp_block_nr = AF_PACKET_TX_BLOCK_NR;
  tx_req->tp_frame_nr = AF_PACKET_TX_BLOCK_NR * tx_frames_per_block;

  /*
   * make sure host side of interface is 'UP' before binding AF_PACKET
   * socket on it.
   */
  if ((fd2 = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to create AF_UNIX socket: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  clib_memcpy (ifr.ifr_name, (const char *) arg->host_if_name,
	       vec_len (arg->host_if_name));
  if (ioctl (fd2, SIOCGIFINDEX, &ifr) < 0)
    {
      vlib_log_debug (
	apm->log_class,
	"Failed to retrieve the interface (%s) index: %s (errno %d)",
	arg->host_if_name, strerror (errno), errno);
      ret = VNET_API_ERROR_INVALID_INTERFACE;
      goto error;
    }

  host_if_index = ifr.ifr_ifindex;
  if (ioctl (fd2, SIOCGIFFLAGS, &ifr) < 0)
    {
      vlib_log_debug (apm->log_class,
		      "Failed to get the active flag: %s (errno %d)",
		      strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if (!(ifr.ifr_flags & IFF_UP))
    {
      ifr.ifr_flags |= IFF_UP;
      if (ioctl (fd2, SIOCSIFFLAGS, &ifr) < 0)
	{
	  vlib_log_debug (apm->log_class,
			  "Failed to set the active flag: %s (errno %d)",
			  strerror (errno), errno);
	  ret = VNET_API_ERROR_SYSCALL_ERROR_1;
	  goto error;
	}
    }

  if (fd2 > -1)
    {
      close (fd2);
      fd2 = -1;
    }

  ret = create_packet_v2_sock (host_if_index, rx_req, tx_req, &fd, &ring);

  if (ret != 0)
    goto error;

  ret = is_bridge (arg->host_if_name);

  if (ret == 0)			/* is a bridge, ignore state */
    host_if_index = -1;

  /* So far everything looks good, let's create interface */
  pool_get (apm->interfaces, apif);
  if_index = apif - apm->interfaces;

  apif->host_if_index = host_if_index;
  apif->fd = fd;
  apif->rx_ring = ring;
  apif->tx_ring = ring + rx_req->tp_block_size * rx_req->tp_block_nr;
  apif->rx_req = rx_req;
  apif->tx_req = tx_req;
  apif->host_if_name = host_if_name_dup;
  apif->per_interface_next_index = ~0;
  apif->next_tx_frame = 0;
  apif->next_rx_frame = 0;
  apif->mode = arg->mode;

  ret = af_packet_read_mtu (apif);
  if (ret != 0)
    goto error;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&apif->lockp);

  if (apif->mode != AF_PACKET_IF_MODE_IP)
    {
      vnet_eth_interface_registration_t eir = {};
      /*use configured or generate random MAC address */
      if (arg->hw_addr)
	clib_memcpy (hw_addr, arg->hw_addr, 6);
      else
	{
	  f64 now = vlib_time_now (vm);
	  u32 rnd;
	  rnd = (u32) (now * 1e6);
	  rnd = random_u32 (&rnd);

	  clib_memcpy (hw_addr + 2, &rnd, sizeof (rnd));
	  hw_addr[0] = 2;
	  hw_addr[1] = 0xfe;
	}

      eir.dev_class_index = af_packet_device_class.index;
      eir.dev_instance = if_index;
      eir.address = hw_addr;
      eir.cb.set_mtu = af_packet_eth_set_mtu;
      apif->hw_if_index = vnet_eth_register_interface (vnm, &eir);
    }
  else
    {
      apif->hw_if_index = vnet_register_interface (
	vnm, af_packet_device_class.index, if_index,
	af_packet_ip_device_hw_interface_class.index, if_index);
    }
  sw = vnet_get_hw_sw_interface (vnm, apif->hw_if_index);
  apif->sw_if_index = sw->sw_if_index;
  vnet_hw_if_set_input_node (vnm, apif->hw_if_index,
			     af_packet_input_node.index);
  apif->queue_index = vnet_hw_if_register_rx_queue (vnm, apif->hw_if_index, 0,
						    VNET_HW_IF_RXQ_THREAD_ANY);

  vnet_hw_if_set_caps (vnm, apif->hw_if_index, VNET_HW_IF_CAP_INT_MODE);
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  vnet_hw_if_set_rx_queue_mode (vnm, apif->queue_index,
				VNET_HW_IF_RX_MODE_INTERRUPT);
  vnet_hw_if_update_runtime_data (vnm, apif->hw_if_index);
  {
    clib_file_t template = { 0 };
    template.read_function = af_packet_fd_read_ready;
    template.file_descriptor = fd;
    template.private_data = if_index;
    template.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
    template.description =
      format (0, "%U", format_af_packet_device_name, if_index);
    apif->clib_file_index = clib_file_add (&file_main, &template);
  }
  vnet_hw_if_set_rx_queue_file_index (vnm, apif->queue_index,
				      apif->clib_file_index);

  mhash_set_mem (&apm->if_index_by_host_if_name, host_if_name_dup, &if_index,
		 0);
  arg->sw_if_index = apif->sw_if_index;

  return 0;

error:
  if (fd2 > -1)
    {
      close (fd2);
      fd2 = -1;
    }
  vec_free (host_if_name_dup);
  vec_free (rx_req);
  vec_free (tx_req);
  return ret;
}

int
af_packet_delete_if (u8 *host_if_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif;
  uword *p;
  uword if_index;
  u32 ring_sz;

  p = mhash_get (&apm->if_index_by_host_if_name, host_if_name);
  if (p == NULL)
    {
      vlib_log_warn (apm->log_class, "Host interface %s does not exist",
		     host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  apif = pool_elt_at_index (apm->interfaces, p[0]);
  if_index = apif - apm->interfaces;

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index, 0);

  /* clean up */
  if (apif->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + apif->clib_file_index);
      apif->clib_file_index = ~0;
    }
  else
    close (apif->fd);

  ring_sz = apif->rx_req->tp_block_size * apif->rx_req->tp_block_nr +
    apif->tx_req->tp_block_size * apif->tx_req->tp_block_nr;
  if (munmap (apif->rx_ring, ring_sz))
    vlib_log_warn (apm->log_class,
		   "Host interface %s could not free rx/tx ring",
		   host_if_name);
  apif->rx_ring = NULL;
  apif->tx_ring = NULL;
  apif->fd = -1;

  vec_free (apif->rx_req);
  apif->rx_req = NULL;
  vec_free (apif->tx_req);
  apif->tx_req = NULL;

  vec_free (apif->host_if_name);
  apif->host_if_name = NULL;
  apif->host_if_index = -1;

  mhash_unset (&apm->if_index_by_host_if_name, host_if_name, &if_index);

  if (apif->mode != AF_PACKET_IF_MODE_IP)
    ethernet_delete_interface (vnm, apif->hw_if_index);
  else
    vnet_delete_hw_interface (vnm, apif->hw_if_index);

  pool_put (apm->interfaces, apif);

  return 0;
}

int
af_packet_set_l4_cksum_offload (u32 sw_if_index, u8 set)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  vnet_hw_if_caps_t caps =
    VNET_HW_IF_CAP_TX_TCP_CKSUM | VNET_HW_IF_CAP_TX_UDP_CKSUM;
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);

  if (hw->dev_class_index != af_packet_device_class.index)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if (set)
    vnet_hw_if_set_caps (vnm, hw->hw_if_index, caps);
  else
    vnet_hw_if_unset_caps (vnm, hw->hw_if_index, caps);

  return 0;
}

int
af_packet_dump_ifs (af_packet_if_detail_t ** out_af_packet_ifs)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif;
  af_packet_if_detail_t *r_af_packet_ifs = NULL;
  af_packet_if_detail_t *af_packet_if = NULL;

  pool_foreach (apif, apm->interfaces)
     {
      vec_add2 (r_af_packet_ifs, af_packet_if, 1);
      af_packet_if->sw_if_index = apif->sw_if_index;
      if (apif->host_if_name)
	{
	  clib_memcpy (af_packet_if->host_if_name, apif->host_if_name,
		       MIN (ARRAY_LEN (af_packet_if->host_if_name) - 1,
		       strlen ((const char *) apif->host_if_name)));
	}
    }

  *out_af_packet_ifs = r_af_packet_ifs;

  return 0;
}

static clib_error_t *
af_packet_init (vlib_main_t * vm)
{
  af_packet_main_t *apm = &af_packet_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  clib_memset (apm, 0, sizeof (af_packet_main_t));

  mhash_init_vec_string (&apm->if_index_by_host_if_name, sizeof (uword));

  vec_validate_aligned (apm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  apm->log_class = vlib_log_register_class ("af_packet", 0);
  vlib_log_debug (apm->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (af_packet_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
