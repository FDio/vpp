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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/af_packet/af_packet.h>

#define AF_PACKET_DEBUG_SOCKET		0

#define AF_PACKET_TX_FRAMES_PER_BLOCK	1024
#define AF_PACKET_TX_FRAME_SIZE	 	(2048 * 5)
#define AF_PACKET_TX_BLOCK_NR		1
#define AF_PACKET_TX_FRAME_NR		(AF_PACKET_TX_BLOCK_NR * \
					 AF_PACKET_TX_FRAMES_PER_BLOCK)
#define AF_PACKET_TX_BLOCK_SIZE	 	(AF_PACKET_TX_FRAME_SIZE * \
					 AF_PACKET_TX_FRAMES_PER_BLOCK)

#define AF_PACKET_RX_FRAMES_PER_BLOCK	1024
#define AF_PACKET_RX_FRAME_SIZE	 	(2048 * 5)
#define AF_PACKET_RX_BLOCK_NR		1
#define AF_PACKET_RX_FRAME_NR		(AF_PACKET_RX_BLOCK_NR * \
					 AF_PACKET_RX_FRAMES_PER_BLOCK)
#define AF_PACKET_RX_BLOCK_SIZE		(AF_PACKET_RX_FRAME_SIZE * \
					 AF_PACKET_RX_FRAMES_PER_BLOCK)

#if AF_PACKET_DEBUG_SOCKET == 1
#define DBG_SOCK(args...) clib_warning(args);
#else
#define DBG_SOCK(args...)
#endif

/*defined in net/if.h but clashes with dpdk headers */
unsigned int if_nametoindex (const char *ifname);

typedef struct tpacket_req tpacket_req_t;

static u32
af_packet_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			   u32 flags)
{
  clib_error_t *error;
  u8 *s;
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hi->dev_instance);

  if (ETHERNET_INTERFACE_FLAG_MTU == (flags & ETHERNET_INTERFACE_FLAG_MTU))
    {
      s = format (0, "/sys/class/net/%s/mtu%c", apif->host_if_name, 0);

      error = clib_sysfs_write ((char *) s, "%d", hi->max_packet_bytes);
      vec_free (s);

      if (error)
	{
	  clib_error_report (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}
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
  vnet_device_input_set_interrupt_pending (vnm, apif->hw_if_index, 0);

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
  int ret, err;
  struct sockaddr_ll sll;
  int ver = TPACKET_V2;
  socklen_t req_sz = sizeof (struct tpacket_req);
  u32 ring_sz = rx_req->tp_block_size * rx_req->tp_block_nr +
    tx_req->tp_block_size * tx_req->tp_block_nr;

  if ((*fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
    {
      DBG_SOCK ("Failed to create socket");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if ((err =
       setsockopt (*fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof (ver))) < 0)
    {
      DBG_SOCK ("Failed to set rx packet interface version");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  int opt = 1;
  if ((err =
       setsockopt (*fd, SOL_PACKET, PACKET_LOSS, &opt, sizeof (opt))) < 0)
    {
      DBG_SOCK ("Failed to set packet tx ring error handling option");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if ((err =
       setsockopt (*fd, SOL_PACKET, PACKET_RX_RING, rx_req, req_sz)) < 0)
    {
      DBG_SOCK ("Failed to set packet rx ring options");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  if ((err =
       setsockopt (*fd, SOL_PACKET, PACKET_TX_RING, tx_req, req_sz)) < 0)
    {
      DBG_SOCK ("Failed to set packet rx ring options");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  *ring =
    mmap (NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, *fd,
	  0);
  if (*ring == MAP_FAILED)
    {
      DBG_SOCK ("mmap failure");
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  memset (&sll, 0, sizeof (sll));
  sll.sll_family = PF_PACKET;
  sll.sll_protocol = htons (ETH_P_ALL);
  sll.sll_ifindex = host_if_index;

  if ((err = bind (*fd, (struct sockaddr *) &sll, sizeof (sll))) < 0)
    {
      DBG_SOCK ("Failed to bind rx packet socket (error %d)", err);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  return 0;
error:
  if (*fd >= 0)
    close (*fd);
  *fd = -1;
  return ret;
}

int
af_packet_create_if (vlib_main_t * vm, u8 * host_if_name, u8 * hw_addr_set,
		     u32 * sw_if_index)
{
  af_packet_main_t *apm = &af_packet_main;
  int ret, fd = -1;
  struct tpacket_req *rx_req = 0;
  struct tpacket_req *tx_req = 0;
  u8 *ring = 0;
  af_packet_if_t *apif = 0;
  u8 hw_addr[6];
  clib_error_t *error;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_main_t *vnm = vnet_get_main ();
  uword *p;
  uword if_index;
  u8 *host_if_name_dup = vec_dup (host_if_name);
  int host_if_index = -1;

  p = mhash_get (&apm->if_index_by_host_if_name, host_if_name);
  if (p)
    {
      return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
    }

  vec_validate (rx_req, 0);
  rx_req->tp_block_size = AF_PACKET_RX_BLOCK_SIZE;
  rx_req->tp_frame_size = AF_PACKET_RX_FRAME_SIZE;
  rx_req->tp_block_nr = AF_PACKET_RX_BLOCK_NR;
  rx_req->tp_frame_nr = AF_PACKET_RX_FRAME_NR;

  vec_validate (tx_req, 0);
  tx_req->tp_block_size = AF_PACKET_TX_BLOCK_SIZE;
  tx_req->tp_frame_size = AF_PACKET_TX_FRAME_SIZE;
  tx_req->tp_block_nr = AF_PACKET_TX_BLOCK_NR;
  tx_req->tp_frame_nr = AF_PACKET_TX_FRAME_NR;

  host_if_index = if_nametoindex ((const char *) host_if_name);

  if (!host_if_index)
    {
      DBG_SOCK ("Wrong host interface name");
      return VNET_API_ERROR_INVALID_INTERFACE;
    }

  ret = create_packet_v2_sock (host_if_index, rx_req, tx_req, &fd, &ring);

  if (ret != 0)
    goto error;

  ret = is_bridge (host_if_name);

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

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&apif->lockp);

  {
    clib_file_t template = { 0 };
    template.read_function = af_packet_fd_read_ready;
    template.file_descriptor = fd;
    template.private_data = if_index;
    template.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
    apif->clib_file_index = clib_file_add (&file_main, &template);
  }

  /*use configured or generate random MAC address */
  if (hw_addr_set)
    clib_memcpy (hw_addr, hw_addr_set, 6);
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

  error = ethernet_register_interface (vnm, af_packet_device_class.index,
				       if_index, hw_addr, &apif->hw_if_index,
				       af_packet_eth_flag_change);

  if (error)
    {
      memset (apif, 0, sizeof (*apif));
      pool_put (apm->interfaces, apif);
      clib_error_report (error);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, apif->hw_if_index);
  hw = vnet_get_hw_interface (vnm, apif->hw_if_index);
  apif->sw_if_index = sw->sw_if_index;
  vnet_hw_interface_set_input_node (vnm, apif->hw_if_index,
				    af_packet_input_node.index);

  vnet_hw_interface_assign_rx_thread (vnm, apif->hw_if_index, 0,	/* queue */
				      ~0 /* any cpu */ );

  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  vnet_hw_interface_set_rx_mode (vnm, apif->hw_if_index, 0,
				 VNET_HW_INTERFACE_RX_MODE_INTERRUPT);

  mhash_set_mem (&apm->if_index_by_host_if_name, host_if_name_dup, &if_index,
		 0);
  if (sw_if_index)
    *sw_if_index = apif->sw_if_index;

  return 0;

error:
  vec_free (host_if_name_dup);
  vec_free (rx_req);
  vec_free (tx_req);
  return ret;
}

int
af_packet_delete_if (vlib_main_t * vm, u8 * host_if_name)
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
      clib_warning ("Host interface %s does not exist", host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  apif = pool_elt_at_index (apm->interfaces, p[0]);
  if_index = apif - apm->interfaces;

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, apif->hw_if_index, 0);
  vnet_hw_interface_unassign_rx_thread (vnm, apif->hw_if_index, 0);

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
    clib_warning ("Host interface %s could not free rx/tx ring",
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

  ethernet_delete_interface (vnm, apif->hw_if_index);

  pool_put (apm->interfaces, apif);

  return 0;
}

static clib_error_t *
af_packet_init (vlib_main_t * vm)
{
  af_packet_main_t *apm = &af_packet_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (apm, 0, sizeof (af_packet_main_t));

  mhash_init_vec_string (&apm->if_index_by_host_if_name, sizeof (uword));

  vec_validate_aligned (apm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

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
