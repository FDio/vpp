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
#include <vnet/interface/tx_queue_funcs.h>

#include <vnet/devices/af_packet/af_packet.h>

af_packet_main_t af_packet_main;

VNET_HW_INTERFACE_CLASS (af_packet_ip_device_hw_interface_class, static) = {
  .name = "af-packet-ip-device",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

#define AF_PACKET_DEFAULT_TX_FRAMES_PER_BLOCK 1024
#define AF_PACKET_DEFAULT_TX_FRAME_SIZE	      (2048 * 33) // GSO packet of 64KB
#define AF_PACKET_TX_BLOCK_NR		1

#define AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK_V2 1024
#define AF_PACKET_DEFAULT_RX_FRAME_SIZE_V2	 (2048 * 33) // GSO packet of 64KB
#define AF_PACKET_RX_BLOCK_NR_V2		 1

#define AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK 32
#define AF_PACKET_DEFAULT_RX_FRAME_SIZE	      2048
#define AF_PACKET_RX_BLOCK_NR		      160

/*defined in net/if.h but clashes with dpdk headers */
unsigned int if_nametoindex (const char *ifname);

static clib_error_t *
af_packet_eth_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hi,
				  u32 frame_size)
{
  clib_error_t *error, *rv;
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif = pool_elt_at_index (apm->interfaces, hi->dev_instance);

  error = vnet_netlink_set_link_mtu (apif->host_if_index,
				     frame_size + hi->frame_overhead);

  if (error)
    {
      vlib_log_err (apm->log_class, "netlink failed to change MTU: %U",
		    format_clib_error, error);
      rv = vnet_error (VNET_ERR_SYSCALL_ERROR_1, "netlink error: %U",
		       format_clib_error, error);
      clib_error_free (error);
      return rv;
    }
  else
    apif->host_mtu = frame_size + hi->frame_overhead;
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
  vnet_main_t *vnm = vnet_get_main ();

  /* Schedule the rx node */
  vnet_hw_if_rx_queue_set_int_pending (vnm, uf->private_data);
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

static void
af_packet_set_rx_queues (vlib_main_t *vm, af_packet_if_t *apif)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_packet_queue_t *rx_queue;

  vnet_hw_if_set_input_node (vnm, apif->hw_if_index,
			     af_packet_input_node.index);

  vec_foreach (rx_queue, apif->rx_queues)
    {
      rx_queue->queue_index = vnet_hw_if_register_rx_queue (
	vnm, apif->hw_if_index, rx_queue->queue_id, VNET_HW_IF_RXQ_THREAD_ANY);

      {
	clib_file_t template = { 0 };
	template.read_function = af_packet_fd_read_ready;
	template.file_descriptor = rx_queue->fd;
	template.private_data = rx_queue->queue_index;
	template.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
	template.description =
	  format (0, "%U queue %u", format_af_packet_device_name,
		  apif->dev_instance, rx_queue->queue_id);
	rx_queue->clib_file_index = clib_file_add (&file_main, &template);
      }
      vnet_hw_if_set_rx_queue_file_index (vnm, rx_queue->queue_index,
					  rx_queue->clib_file_index);
      vnet_hw_if_set_rx_queue_mode (vnm, rx_queue->queue_index,
				    VNET_HW_IF_RX_MODE_INTERRUPT);
      rx_queue->mode = VNET_HW_IF_RX_MODE_INTERRUPT;
    }
  vnet_hw_if_update_runtime_data (vnm, apif->hw_if_index);
}

static void
af_packet_set_tx_queues (vlib_main_t *vm, af_packet_if_t *apif)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_packet_main_t *apm = &af_packet_main;
  af_packet_queue_t *tx_queue;

  vec_foreach (tx_queue, apif->tx_queues)
    {
      tx_queue->queue_index = vnet_hw_if_register_tx_queue (
	vnm, apif->hw_if_index, tx_queue->queue_id);
    }

  if (apif->num_txqs == 0)
    {
      vlib_log_err (apm->log_class, "Interface %U has 0 txq",
		    format_vnet_hw_if_index_name, vnm, apif->hw_if_index);
      return;
    }

  for (u32 j = 0; j < vlib_get_n_threads (); j++)
    {
      u32 qi = apif->tx_queues[j % apif->num_txqs].queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi, j);
    }

  vnet_hw_if_update_runtime_data (vnm, apif->hw_if_index);
}

static int
create_packet_sock (int host_if_index, tpacket_req_u_t *rx_req,
		    tpacket_req_u_t *tx_req, int *fd, af_packet_ring_t *ring,
		    u32 fanout_id, af_packet_if_flags_t *flags, int ver)
{
  af_packet_main_t *apm = &af_packet_main;
  struct sockaddr_ll sll;
  socklen_t req_sz = sizeof (tpacket_req3_t);
  int ret;
  u32 ring_sz = 0;

  if ((*fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
    {
      vlib_log_err (apm->log_class,
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
      vlib_log_err (apm->log_class,
		    "Failed to bind rx packet socket: %s (errno %d)",
		    strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if (setsockopt (*fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof (ver)) < 0)
    {
      vlib_log_err (apm->log_class,
		    "Failed to set rx packet interface version: %s (errno %d)",
		    strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  int opt = 1;
  if (setsockopt (*fd, SOL_PACKET, PACKET_LOSS, &opt, sizeof (opt)) < 0)
    {
      vlib_log_err (
	apm->log_class,
	"Failed to set packet tx ring error handling option: %s (errno %d)",
	strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if (*flags & AF_PACKET_IF_FLAGS_CKSUM_GSO)
    {

      int opt2 = 1;
      if (setsockopt (*fd, SOL_PACKET, PACKET_VNET_HDR, &opt2, sizeof (opt2)) <
	  0)
	{
	  // remove the flag
	  *flags &= ~AF_PACKET_IF_FLAGS_CKSUM_GSO;
	  vlib_log_debug (apm->log_class,
			  "Failed to set packet vnet hdr error handling "
			  "option: %s (errno %d)",
			  strerror (errno), errno);
	}
    }

#if defined(PACKET_QDISC_BYPASS)
  if (*flags & AF_PACKET_IF_FLAGS_QDISC_BYPASS)
    /* Introduced with Linux 3.14 so the ifdef should eventually be removed  */
    if (setsockopt (*fd, SOL_PACKET, PACKET_QDISC_BYPASS, &opt, sizeof (opt)) <
	0)
      {
	// remove the flag
	*flags &= ~AF_PACKET_IF_FLAGS_QDISC_BYPASS;
	vlib_log_debug (apm->log_class,
			"Failed to set qdisc bypass error "
			"handling option: %s (errno %d)",
			strerror (errno), errno);
      }
#endif

  if (rx_req)
    {
      if (*flags & AF_PACKET_IF_FLAGS_FANOUT)
	{
	  int fanout = ((fanout_id & 0xffff) | ((PACKET_FANOUT_HASH) << 16));
	  if (setsockopt (*fd, SOL_PACKET, PACKET_FANOUT, &fanout,
			  sizeof (fanout)) < 0)
	    {
	      // remove the flag
	      *flags &= ~AF_PACKET_IF_FLAGS_FANOUT;
	      vlib_log_err (apm->log_class,
			    "Failed to set fanout options: %s (errno %d)",
			    strerror (errno), errno);
	      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
	      goto error;
	    }
	}
      if (ver == TPACKET_V2)
	{
	  req_sz = sizeof (tpacket_req_t);
	  ring_sz += rx_req->req.tp_block_size * rx_req->req.tp_block_nr;
	}
      else
	ring_sz += rx_req->req3.tp_block_size * rx_req->req3.tp_block_nr;
      if (setsockopt (*fd, SOL_PACKET, PACKET_RX_RING, rx_req, req_sz) < 0)
	{
	  vlib_log_err (apm->log_class,
			"Failed to set packet rx ring options: %s (errno %d)",
			strerror (errno), errno);
	  ret = VNET_API_ERROR_SYSCALL_ERROR_1;
	  goto error;
	}
    }

  if (tx_req)
    {
      if (ver == TPACKET_V2)
	{
	  req_sz = sizeof (tpacket_req_t);
	  ring_sz += tx_req->req.tp_block_size * tx_req->req.tp_block_nr;
	}
      else
	ring_sz += tx_req->req3.tp_block_size * tx_req->req3.tp_block_nr;
      if (setsockopt (*fd, SOL_PACKET, PACKET_TX_RING, tx_req, req_sz) < 0)
	{
	  vlib_log_err (apm->log_class,
			"Failed to set packet tx ring options: %s (errno %d)",
			strerror (errno), errno);
	  ret = VNET_API_ERROR_SYSCALL_ERROR_1;
	  goto error;
	}
    }
  ring->ring_start_addr = mmap (NULL, ring_sz, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_LOCKED, *fd, 0);
  if (ring->ring_start_addr == MAP_FAILED)
    {
      vlib_log_err (apm->log_class, "mmap failure: %s (errno %d)",
		    strerror (errno), errno);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  ring->ring_size = ring_sz;

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
af_packet_queue_init (vlib_main_t *vm, af_packet_if_t *apif,
		      af_packet_create_if_arg_t *arg,
		      af_packet_queue_t *rx_queue, af_packet_queue_t *tx_queue,
		      u8 queue_id)
{
  af_packet_main_t *apm = &af_packet_main;
  tpacket_req_u_t *rx_req = 0;
  tpacket_req_u_t *tx_req = 0;
  int ret, fd = -1;
  af_packet_ring_t ring = { 0 };
  u8 *ring_addr = 0;
  u32 rx_frames_per_block, tx_frames_per_block;
  u32 rx_frame_size, tx_frame_size;
  u32 i = 0;

  if (rx_queue)
    {
      rx_frames_per_block = arg->rx_frames_per_block ?
				    arg->rx_frames_per_block :
				    ((apif->version == TPACKET_V3) ?
				       AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK :
				       AF_PACKET_DEFAULT_RX_FRAMES_PER_BLOCK_V2);

      rx_frame_size =
	arg->rx_frame_size ?
		arg->rx_frame_size :
		((apif->version == TPACKET_V3) ? AF_PACKET_DEFAULT_RX_FRAME_SIZE :
						 AF_PACKET_DEFAULT_RX_FRAME_SIZE_V2);
      vec_validate (rx_queue->rx_req, 0);
      rx_queue->rx_req->req.tp_block_size =
	rx_frame_size * rx_frames_per_block;
      rx_queue->rx_req->req.tp_frame_size = rx_frame_size;
      rx_queue->rx_req->req.tp_block_nr = (apif->version == TPACKET_V3) ?
						  AF_PACKET_RX_BLOCK_NR :
						  AF_PACKET_RX_BLOCK_NR_V2;
      rx_queue->rx_req->req.tp_frame_nr =
	rx_queue->rx_req->req.tp_block_nr * rx_frames_per_block;
      if (apif->version == TPACKET_V3)
	{
	  rx_queue->rx_req->req3.tp_retire_blk_tov = 1; // 1 ms block timout
	  rx_queue->rx_req->req3.tp_feature_req_word = 0;
	  rx_queue->rx_req->req3.tp_sizeof_priv = 0;
	}
      rx_req = rx_queue->rx_req;
    }
  if (tx_queue)
    {
      tx_frames_per_block = arg->tx_frames_per_block ?
				    arg->tx_frames_per_block :
				    AF_PACKET_DEFAULT_TX_FRAMES_PER_BLOCK;
      tx_frame_size = arg->tx_frame_size ? arg->tx_frame_size :
						 AF_PACKET_DEFAULT_TX_FRAME_SIZE;

      vec_validate (tx_queue->tx_req, 0);
      tx_queue->tx_req->req.tp_block_size =
	tx_frame_size * tx_frames_per_block;
      tx_queue->tx_req->req.tp_frame_size = tx_frame_size;
      tx_queue->tx_req->req.tp_block_nr = AF_PACKET_TX_BLOCK_NR;
      tx_queue->tx_req->req.tp_frame_nr =
	AF_PACKET_TX_BLOCK_NR * tx_frames_per_block;
      if (apif->version == TPACKET_V3)
	{
	  tx_queue->tx_req->req3.tp_retire_blk_tov = 0;
	  tx_queue->tx_req->req3.tp_sizeof_priv = 0;
	  tx_queue->tx_req->req3.tp_feature_req_word = 0;
	}
      tx_req = tx_queue->tx_req;
    }

  if (rx_queue || tx_queue)
    {
      ret =
	create_packet_sock (apif->host_if_index, rx_req, tx_req, &fd, &ring,
			    apif->dev_instance, &arg->flags, apif->version);

      if (ret != 0)
	goto error;

      vec_add1 (apif->rings, ring);
      ring_addr = ring.ring_start_addr;
    }

  if (rx_queue)
    {
      rx_queue->fd = fd;
      vec_validate (rx_queue->rx_ring, rx_queue->rx_req->req.tp_block_nr - 1);
      vec_foreach_index (i, rx_queue->rx_ring)
	{
	  rx_queue->rx_ring[i] =
	    ring_addr + i * rx_queue->rx_req->req.tp_block_size;
	}

      rx_queue->next_rx_block = 0;
      rx_queue->queue_id = queue_id;
      rx_queue->is_rx_pending = 0;
      ring_addr = ring_addr + rx_queue->rx_req->req.tp_block_size *
				rx_queue->rx_req->req.tp_block_nr;
    }

  if (tx_queue)
    {
      tx_queue->fd = fd;
      vec_validate (tx_queue->tx_ring, tx_queue->tx_req->req.tp_block_nr - 1);
      vec_foreach_index (i, tx_queue->tx_ring)
	{
	  tx_queue->tx_ring[i] =
	    ring_addr + i * tx_queue->tx_req->req.tp_block_size;
	}

      tx_queue->next_tx_frame = 0;
      tx_queue->queue_id = queue_id;
      tx_queue->is_tx_pending = 0;
      clib_spinlock_init (&tx_queue->lockp);
    }

  return 0;
error:
  vlib_log_err (apm->log_class, "Failed to set queue %u error", queue_id);
  if (rx_queue)
    vec_free (rx_queue->rx_req);
  if (tx_queue)
    vec_free (tx_queue->tx_req);
  return ret;
}

int
af_packet_device_init (vlib_main_t *vm, af_packet_if_t *apif,
		       af_packet_create_if_arg_t *args)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_queue_t *rx_queue = 0;
  af_packet_queue_t *tx_queue = 0;
  u16 nq = clib_min (args->num_rxqs, args->num_txqs);
  u16 i = 0;
  int ret = 0;

  // enable fanout feature for multi-rxqs
  if (args->num_rxqs > 1)
    args->flags |= AF_PACKET_IF_FLAGS_FANOUT;

  vec_validate (apif->rx_queues, args->num_rxqs - 1);
  vec_validate (apif->tx_queues, args->num_txqs - 1);

  for (; i < nq; i++)
    {
      rx_queue = vec_elt_at_index (apif->rx_queues, i);
      tx_queue = vec_elt_at_index (apif->tx_queues, i);
      ret = af_packet_queue_init (vm, apif, args, rx_queue, tx_queue, i);
      if (ret != 0)
	goto error;
    }

  if (args->num_rxqs > args->num_txqs)
    {
      for (; i < args->num_rxqs; i++)
	{
	  rx_queue = vec_elt_at_index (apif->rx_queues, i);
	  ret = af_packet_queue_init (vm, apif, args, rx_queue, 0, i);
	  if (ret != 0)
	    goto error;
	}
    }
  else if (args->num_txqs > args->num_rxqs)
    {
      for (; i < args->num_txqs; i++)
	{
	  tx_queue = vec_elt_at_index (apif->tx_queues, i);
	  ret = af_packet_queue_init (vm, apif, args, 0, tx_queue, i);
	  if (ret != 0)
	    goto error;
	}
    }

  apif->num_rxqs = args->num_rxqs;
  apif->num_txqs = args->num_txqs;

  return 0;
error:
  vlib_log_err (apm->log_class, "Failed to init device error");
  return ret;
}

int
af_packet_create_if (af_packet_create_if_arg_t *arg)
{
  af_packet_main_t *apm = &af_packet_main;
  vlib_main_t *vm = vlib_get_main ();
  int fd2 = -1;
  struct ifreq ifr;
  af_packet_if_t *apif = 0;
  u8 hw_addr[6];
  vnet_sw_interface_t *sw;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_if_caps_t caps = VNET_HW_IF_CAP_INT_MODE;
  uword *p;
  uword if_index;
  u8 *host_if_name_dup = 0;
  int host_if_index = -1;
  int ret = 0;

  p = mhash_get (&apm->if_index_by_host_if_name, arg->host_if_name);
  if (p)
    {
      apif = vec_elt_at_index (apm->interfaces, p[0]);
      arg->sw_if_index = apif->sw_if_index;
      return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  host_if_name_dup = vec_dup (arg->host_if_name);

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

  ret = is_bridge (arg->host_if_name);
  if (ret == 0)			/* is a bridge, ignore state */
    host_if_index = -1;

  /* So far everything looks good, let's create interface */
  pool_get (apm->interfaces, apif);
  if_index = apif - apm->interfaces;

  apif->dev_instance = if_index;
  apif->host_if_index = host_if_index;
  apif->host_if_name = host_if_name_dup;
  apif->per_interface_next_index = ~0;
  apif->mode = arg->mode;

  if (arg->is_v2)
    apif->version = TPACKET_V2;
  else
    apif->version = TPACKET_V3;

  ret = af_packet_device_init (vm, apif, arg);
  if (ret != 0)
    goto error;

  ret = af_packet_read_mtu (apif);
  if (ret != 0)
    goto error;


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
      eir.dev_instance = apif->dev_instance;
      eir.address = hw_addr;
      eir.cb.set_max_frame_size = af_packet_eth_set_max_frame_size;
      apif->hw_if_index = vnet_eth_register_interface (vnm, &eir);
    }
  else
    {
      apif->hw_if_index = vnet_register_interface (
	vnm, af_packet_device_class.index, apif->dev_instance,
	af_packet_ip_device_hw_interface_class.index, apif->dev_instance);
    }

  sw = vnet_get_hw_sw_interface (vnm, apif->hw_if_index);
  apif->sw_if_index = sw->sw_if_index;

  af_packet_set_rx_queues (vm, apif);
  af_packet_set_tx_queues (vm, apif);

  if (arg->flags & AF_PACKET_IF_FLAGS_FANOUT)
    apif->is_fanout_enabled = 1;

  apif->is_qdisc_bypass_enabled =
    (arg->flags & AF_PACKET_IF_FLAGS_QDISC_BYPASS);

  if (arg->flags & AF_PACKET_IF_FLAGS_CKSUM_GSO)
    apif->is_cksum_gso_enabled = 1;

  if (apif->is_cksum_gso_enabled)
    caps |= VNET_HW_IF_CAP_TCP_GSO | VNET_HW_IF_CAP_TX_IP4_CKSUM |
	    VNET_HW_IF_CAP_TX_TCP_CKSUM | VNET_HW_IF_CAP_TX_UDP_CKSUM;

  vnet_hw_if_set_caps (vnm, apif->hw_if_index, caps);
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

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
  if (apif)
    {
      memset (apif, 0, sizeof (*apif));
      pool_put (apm->interfaces, apif);
    }
  return ret;
}

static int
af_packet_rx_queue_free (af_packet_if_t *apif, af_packet_queue_t *rx_queue)
{
  clib_file_del_by_index (&file_main, rx_queue->clib_file_index);
  close (rx_queue->fd);
  rx_queue->fd = -1;
  rx_queue->rx_ring = NULL;
  vec_free (rx_queue->rx_req);
  rx_queue->rx_req = NULL;
  return 0;
}

static int
af_packet_tx_queue_free (af_packet_if_t *apif, af_packet_queue_t *tx_queue)
{
  close (tx_queue->fd);
  tx_queue->fd = -1;
  clib_spinlock_free (&tx_queue->lockp);
  tx_queue->tx_ring = NULL;
  vec_free (tx_queue->tx_req);
  tx_queue->tx_req = NULL;
  return 0;
}

static int
af_packet_ring_free (af_packet_if_t *apif, af_packet_ring_t *ring)
{
  af_packet_main_t *apm = &af_packet_main;

  if (ring)
    {
      // FIXME: unmap the memory
      if (munmap (ring->ring_start_addr, ring->ring_size))
	vlib_log_warn (apm->log_class,
		       "Host interface %s could not free ring %p of size %u",
		       apif->host_if_name, ring->ring_start_addr,
		       ring->ring_size);
      else
	ring->ring_start_addr = 0;
    }

  return 0;
}

int
af_packet_delete_if (u8 *host_if_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif;
  af_packet_queue_t *rx_queue;
  af_packet_queue_t *tx_queue;
  af_packet_ring_t *ring;
  uword *p;

  p = mhash_get (&apm->if_index_by_host_if_name, host_if_name);
  if (p == NULL)
    {
      vlib_log_warn (apm->log_class, "Host interface %s does not exist",
		     host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  apif = pool_elt_at_index (apm->interfaces, p[0]);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index, 0);
  if (apif->mode != AF_PACKET_IF_MODE_IP)
    ethernet_delete_interface (vnm, apif->hw_if_index);
  else
    vnet_delete_hw_interface (vnm, apif->hw_if_index);

  /* clean up */
  vec_foreach (rx_queue, apif->rx_queues)
    af_packet_rx_queue_free (apif, rx_queue);
  vec_foreach (tx_queue, apif->tx_queues)
    af_packet_tx_queue_free (apif, tx_queue);
  vec_foreach (ring, apif->rings)
    af_packet_ring_free (apif, ring);

  vec_free (apif->rx_queues);
  apif->rx_queues = NULL;
  vec_free (apif->tx_queues);
  apif->tx_queues = NULL;
  vec_free (apif->rings);
  apif->rings = NULL;

  vec_free (apif->host_if_name);
  apif->host_if_name = NULL;
  apif->host_if_index = -1;

  mhash_unset (&apm->if_index_by_host_if_name, host_if_name, p);

  memset (apif, 0, sizeof (*apif));
  pool_put (apm->interfaces, apif);

  return 0;
}

int
af_packet_set_l4_cksum_offload (u32 sw_if_index, u8 set)
{
  // deprecated ...
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
