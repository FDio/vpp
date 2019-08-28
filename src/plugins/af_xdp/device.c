/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/linux/sysfs.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <af_xdp/af_xdp.h>
#include <af_xdp/xsk_defs.h>

af_xdp_main_t af_xdp_main;

static int
xsk_umem_init (int sfd, struct xdp_umem **umem_out)
{
  af_xdp_main_t *am = &af_xdp_main;
  int rv;
  struct xdp_umem_reg umem_reg;
  struct xdp_umem *umem;

  umem = calloc (1, sizeof (*umem));
  if (!umem)
    {
      vlib_log_err (am->log_class, "not enough memory");
      rv = ENOMEM;
      goto err_calloc;
    }

  umem_reg.headroom = 0;
  umem_reg.chunk_size = FRAME_SIZE;
  umem_reg.len = NUM_FRAMES * umem_reg.chunk_size;
  umem_reg.addr = pointer_to_uword
    (clib_mem_alloc_aligned (umem_reg.len, clib_mem_get_page_size ()));

  if (setsockopt (sfd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof (umem_reg)))
    {
      vlib_log_err (am->log_class, "failed to register umem, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_fq;
    }

  int fill_ring_size = DEFAULT_FILL_RING_SIZE;
  if (setsockopt (sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_ring_size,
		  sizeof (int)))
    {
      vlib_log_err (am->log_class, "failed to set umem Fill ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_fq;
    }

  int completion_ring_size = DEFAULT_COMP_RING_SIZE;
  if (setsockopt (sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
		  &completion_ring_size, sizeof (int)))
    {
      vlib_log_err (am->log_class, "failed to set umem Completion ring, "
		    "errno: %d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_fq;
    }

  socklen_t opt_length;
  struct xdp_mmap_offsets offsets;
  opt_length = sizeof (offsets);
  if (getsockopt (sfd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &opt_length))
    {
      vlib_log_err (am->log_class, "failed to get XDP mmap offsets, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_fq;
    }

  umem->fq.map_size = offsets.fr.desc + DEFAULT_FILL_RING_SIZE * sizeof (u64);
  umem->fq.map = mmap (NULL, umem->fq.map_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, sfd,
		       XDP_UMEM_PGOFF_FILL_RING);
  if (umem->fq.map == MAP_FAILED)
    {
      vlib_log_err (am->log_class, "failed to mmap Fill ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_fq;
    }

  umem->fq.size = DEFAULT_FILL_RING_SIZE;
  umem->fq.producer = umem->fq.map + offsets.fr.producer;
  umem->fq.consumer = umem->fq.map + offsets.fr.consumer;
  umem->fq.ring = umem->fq.map + offsets.fr.desc;
  umem->fq.cached_cons = DEFAULT_FILL_RING_SIZE;

  umem->cq.map_size = offsets.cr.desc + DEFAULT_COMP_RING_SIZE * sizeof (u64);
  umem->cq.map = mmap (NULL, umem->cq.map_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, sfd,
		       XDP_UMEM_PGOFF_COMPLETION_RING);
  if (umem->cq.map == MAP_FAILED)
    {
      vlib_log_err (am->log_class, "failed to mmap Completion ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_cq;
    }

  umem->cq.size = DEFAULT_COMP_RING_SIZE;
  umem->cq.producer = umem->cq.map + offsets.cr.producer;
  umem->cq.consumer = umem->cq.map + offsets.cr.consumer;
  umem->cq.ring = umem->cq.map + offsets.cr.desc;

  umem->frames = (void *) umem_reg.addr;
  umem->fd = sfd;

  *umem_out = umem;
  return 0;

err_mmap_cq:
  if (munmap (umem->fq.map, umem->fq.map_size))
    vlib_log_warn (am->log_class, "failed to unmap Fill ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));
err_mmap_fq:
  free (umem);
err_calloc:
  *umem_out = NULL;
  return rv;
}

static int
xsk_init (int ifindex, u32 queue_id, struct xsk_info **xsk_out)
{
  af_xdp_main_t *am = &af_xdp_main;
  int rv;
  struct sockaddr_xdp sxdp = { };
  int sfd;
  struct xsk_info *xsk;
  u64 i;

  if ((sfd = socket (AF_XDP, SOCK_RAW, 0)) < 0)
    {
      vlib_log_err (am->log_class, "cannot open AF_XDP socket, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_sfd;
    }

  xsk = calloc (1, sizeof (*xsk));
  if (!xsk)
    {
      vlib_log_err (am->log_class, "not enough memory");
      rv = ENOMEM;
      goto err_calloc;
    }

  xsk->sfd = sfd;
  xsk->outstanding_tx = 0;
  rv = xsk_umem_init (sfd, &xsk->umem);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to configure umem");
      goto err_mmap_rx;
    }

  int rx_ring_size = DEFAULT_RX_RING_SIZE;
  if (setsockopt
      (sfd, SOL_XDP, XDP_RX_RING, &rx_ring_size, sizeof (rx_ring_size)))
    {
      vlib_log_err (am->log_class, "failed to set XDP socket RX ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_rx;
    }

  int tx_ring_size = DEFAULT_TX_RING_SIZE;
  if (setsockopt (sfd, SOL_XDP, XDP_TX_RING, &tx_ring_size,
		  sizeof (tx_ring_size)))
    {
      vlib_log_err (am->log_class, "failed to set XDP socket TX ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_rx;
    }

  socklen_t opt_length;
  struct xdp_mmap_offsets offsets;
  opt_length = sizeof (offsets);
  if (getsockopt (sfd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &opt_length))
    {
      vlib_log_err (am->log_class, "failed to get XDP mmap offsets, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_rx;
    }

  /* RX */
  xsk->rx.map_size =
    offsets.rx.desc + DEFAULT_RX_RING_SIZE * sizeof (struct xdp_desc);
  xsk->rx.map = mmap (NULL, xsk->rx.map_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, sfd, XDP_PGOFF_RX_RING);
  if (xsk->rx.map == MAP_FAILED)
    {
      vlib_log_err (am->log_class, "failed to mmap RX ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_rx;
    }

  for (i = 0; i < DEFAULT_RX_RING_SIZE * FRAME_SIZE; i += FRAME_SIZE)
    if (umem_fill_to_kernel (&xsk->umem->fq, &i, 1) != 0)
      {
	vlib_log_err (am->log_class, "failed to put Fill queue to kernel");
	rv = ENOSPC;
	goto err_mmap_tx;
      }

  /* TX */
  xsk->tx.map_size =
    offsets.tx.desc + DEFAULT_TX_RING_SIZE * sizeof (struct xdp_desc);
  xsk->tx.map = mmap (NULL, xsk->tx.map_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, sfd, XDP_PGOFF_TX_RING);
  if (xsk->tx.map == MAP_FAILED)
    {
      vlib_log_err (am->log_class, "failed to mmap TX ring, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_mmap_tx;
    }

  xsk->rx.size = DEFAULT_RX_RING_SIZE;
  xsk->rx.producer = xsk->rx.map + offsets.rx.producer;
  xsk->rx.consumer = xsk->rx.map + offsets.rx.consumer;
  xsk->rx.ring = xsk->rx.map + offsets.rx.desc;

  xsk->tx.size = DEFAULT_TX_RING_SIZE;
  xsk->tx.producer = xsk->tx.map + offsets.tx.producer;
  xsk->tx.consumer = xsk->tx.map + offsets.tx.consumer;
  xsk->tx.ring = xsk->tx.map + offsets.tx.desc;
  xsk->tx.cached_cons = DEFAULT_TX_RING_SIZE;

  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = queue_id;
  sxdp.sxdp_flags = 0;

  if (bind (sfd, (struct sockaddr *) &sxdp, sizeof (sxdp)))
    {
      vlib_log_err (am->log_class, "failed to bind the socket, errno: "
		    "%d \"%s\"", errno, strerror (errno));
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto err_bind;
    }

  *xsk_out = xsk;
  return 0;

err_bind:
  if (munmap (xsk->tx.map, xsk->tx.map_size))
    vlib_log_warn (am->log_class, "failed to munmap TX ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));
err_mmap_tx:
  if (munmap (xsk->rx.map, xsk->rx.map_size))
    vlib_log_warn (am->log_class, "failed to munmap RX ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));
err_mmap_rx:
  free (xsk);
err_calloc:
  close (sfd);
err_sfd:
  *xsk_out = NULL;
  return rv;
}

static void
xsk_umem_destroy (struct xdp_umem **umem)
{
  af_xdp_main_t *am = &af_xdp_main;
  struct xdp_umem *u = *umem;

  if (NULL == u)
    return;

  if (munmap (u->fq.map, u->fq.map_size))
    vlib_log_warn (am->log_class, "failed to unmap Fill ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));

  if (munmap (u->cq.map, u->cq.map_size))
    vlib_log_warn (am->log_class, "failed to unmap Completion ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));

  clib_mem_free (u->frames);
  free (u);
  *umem = NULL;
}

void
xsk_destroy (struct xsk_info **xsk)
{
  af_xdp_main_t *am = &af_xdp_main;
  struct xsk_info *s = *xsk;

  if (NULL == s)
    return;

  if (munmap (s->rx.map, s->rx.map_size))
    vlib_log_warn (am->log_class, "failed to unmap RX ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));

  if (munmap (s->tx.map, s->tx.map_size))
    vlib_log_warn (am->log_class, "failed to unmap TX ring, errno: "
		   "%d \"%s\"", errno, strerror (errno));

  xsk_umem_destroy (&s->umem);
  close (s->sfd);

  free (s);
  *xsk = NULL;
}

static u32
af_xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  clib_error_t *error;
  u8 *s;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  if (flags & ETHERNET_INTERFACE_FLAG_MTU)
    {
      s = format (0, "/sys/class/net/%s/mtu%c", ad->ifname, 0);

      error = clib_sysfs_write ((char *) s, "%d", hw->max_packet_bytes);
      vec_free (s);

      if (error)
	{
	  vlib_log_err (am->log_class,
			"sysfs write failed to change MTU: %U",
			format_clib_error, error);
	  clib_error_free (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}
    }

  return 0;
}

int
open_xsks_map (const u8 * ifname, int *fd_out)
{
#define PATH_MAX	4096

  af_xdp_main_t *am = &af_xdp_main;
  char filename[PATH_MAX];
  int len, fd;

  len = snprintf (filename, PATH_MAX, PIN_BASEDIR "/%s/" XSKMAP_NAME,
		  (char *) ifname);
  if (len < 0)
    {
      vlib_log_err (am->log_class, "error constructing xsks_map path");
      return VNET_API_ERROR_UNSPECIFIED;
    }

  fd = bpf_obj_get (filename);
  if (fd < 0)
    {
      vlib_log_err (am->log_class, "failed to open bpf map file: \'%s\', "
		    "errno: %d \"%s\"", filename, errno, strerror (errno));
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  *fd_out = fd;
  return 0;

#undef PATH_MAX
}

void
af_xdp_delete_if (vlib_main_t * vm, af_xdp_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;
  int xsks_map_fd, rv;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  if (ad->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + ad->clib_file_index);
      ad->clib_file_index = ~0;
    }

  rv = open_xsks_map (ad->ifname, &xsks_map_fd);
  if (!rv)			/* everything is ok */
    {
      rv = bpf_map_delete_elem (xsks_map_fd, &ad->key);
      if (rv)
	vlib_log_err (am->log_class,
		      "failed to delete XDP socket from xskmap");
    }

  xsk_destroy (&ad->xsk);

  vec_free (ad->ifname);
  ad->ifname = NULL;
  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
}

int
check_map_compat (int map_fd, struct bpf_map_info *exp)
{
  af_xdp_main_t *am = &af_xdp_main;
  struct bpf_map_info info = { 0 };
  u32 info_len = sizeof (info);
  int rv;

  if (map_fd < 0)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  rv = bpf_obj_get_info_by_fd (map_fd, &info, &info_len);
  if (rv)
    {
      vlib_log_err (am->log_class,
		    "can't get bpf map info, errno: %d \"%s\"", errno,
		    strerror (errno));
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (exp->key_size && exp->key_size != info.key_size)
    {
      vlib_log_err (am->log_class, "bpf map key size mismatch "
		    "expected: %d, got: %d", exp->key_size, info.key_size);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (exp->value_size && exp->value_size != info.value_size)
    {
      vlib_log_err (am->log_class, "bpf map value size mismatch "
		    "expected: %d, got: %d", exp->value_size,
		    info.value_size);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (exp->max_entries && exp->max_entries != info.max_entries)
    {
      vlib_log_err (am->log_class, "bpf map max. entries mismatch "
		    "expected: %d, got: %d", exp->max_entries,
		    info.max_entries);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (exp->type && exp->type != info.type)
    {
      vlib_log_err (am->log_class, "bpf map type mismatch "
		    "expected: %d, got: %d", exp->type, info.type);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  return 0;
}

int
xsk_if_init (u8 * ifname, u32 key, u32 queue_id, struct xsk_info **xsk_out)
{
  af_xdp_main_t *am = &af_xdp_main;
  int ifindex;
  struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
  int xsks_map_fd;
  int rv;
  struct xsk_info *xsk;
  struct bpf_map_info map_expect = { 0 };

  if ((ifindex = if_nametoindex ((char *) ifname)) == 0)
    {
      vlib_log_err (am->log_class, "interface \"%s\" does not exist", ifname);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (setrlimit (RLIMIT_MEMLOCK, &r))
    {
      vlib_log_err (am->log_class, "setrlimit failed, errno: %d \"%s\"",
		    errno, strerror (errno));
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  rv = open_xsks_map (ifname, &xsks_map_fd);
  if (rv)
    return rv;

  /* Check map info */
  map_expect.key_size = sizeof (int);
  map_expect.value_size = sizeof (int);
  rv = check_map_compat (xsks_map_fd, &map_expect);
  if (rv)
    {
      vlib_log_err (am->log_class, "xskmap compatibility check failed");
      return rv;
    }

  /* Create the socket */
  rv = xsk_init (ifindex, queue_id, &xsk);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to initialize XDP socket");
      return rv;
    }

  /* Insert the socket into xsks_map. */
  rv = bpf_map_update_elem (xsks_map_fd, &key, &xsk->sfd, 0);
  if (rv)
    {
      vlib_log_err (am->log_class, "failed to insert XDP socket into xskmap");
      xsk_destroy (&xsk);
      return rv;
    }

  *xsk_out = xsk;

  return 0;
}

static clib_error_t *
af_xdp_fd_read_ready (clib_file_t * uf)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 idx = uf->private_data;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, idx);

  am->pending_input_bitmap =
    clib_bitmap_set (am->pending_input_bitmap, idx, 1);

  /* Schedule the rx node */
  vnet_device_input_set_interrupt_pending (vnm, ad->hw_if_index,
					   ad->queue_id);

  return 0;
}

clib_error_t *
get_hwaddr (const u8 * ifname, u8 hwaddr[6])
{
  clib_error_t *error = 0;

  int fd;
  struct ifreq ifr;

  memset (&ifr, 0, sizeof (ifr));

  fd = socket (AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy (ifr.ifr_name, (const char *) ifname, IFNAMSIZ - 1);

  if (0 == ioctl (fd, SIOCGIFHWADDR, &ifr))
    clib_memcpy (hwaddr, ifr.ifr_hwaddr.sa_data, 6);
  else
    error = clib_error_return (error, "failed to get hwaddr of '%s'", ifname);

  close (fd);

  return error;
}

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  clib_error_t *error = 0;
  int rv = 0;
  unsigned int ifindex;
  clib_file_t cfile = { 0 };

  if ((ifindex = if_nametoindex ((char *) args->ifname)) == 0)
    {
      args->rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      args->error = clib_error_return (error, "failed to get ifindex of '%s'",
				       args->ifname);
      return;
    }

  pool_get (am->devices, ad);

  if ((rv = xsk_if_init (args->ifname, args->key, args->queue_id, &ad->xsk)))
    {
      args->rv = rv;
      args->error = clib_error_return (error, "failed to create "
				       "interface '%s'", args->ifname);
      goto error;
    }

  ad->ifname = vec_dup (args->ifname);
  ad->ifindex = ifindex;
  ad->key = args->key;
  ad->queue_id = args->queue_id;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  cfile.read_function = af_xdp_fd_read_ready;
  cfile.file_descriptor = ad->xsk->sfd;
  cfile.private_data = ad->dev_instance;
  cfile.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
  cfile.description = format (0, "%U", format_af_xdp_device_name,
			      ad->dev_instance);
  ad->clib_file_index = clib_file_add (&file_main, &cfile);

  error = get_hwaddr (args->ifname, ad->hwaddr);
  if (error)
    goto error;

  error = ethernet_register_interface (vnm, af_xdp_device_class.index,
				       ad->dev_instance, ad->hwaddr,
				       &ad->hw_if_index, af_xdp_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    af_xdp_input_node.index);

  vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, args->queue_id,
				      ~0 /* any cpu */ );
  vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  vnet_hw_interface_set_rx_mode (vnm, ad->hw_if_index, args->queue_id,
				 VNET_HW_INTERFACE_RX_MODE_INTERRUPT);

  return;

error:
  af_xdp_delete_if (vm, ad);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  vlib_log_err (am->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
af_xdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & AF_XDP_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= AF_XDP_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~AF_XDP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
af_xdp_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), af_xdp_input_node.index,
			node_index);
}

static char *af_xdp_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_tx_func_error
#undef _
};

VNET_DEVICE_CLASS_TX_FN (af_xdp_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, rd->dev_instance);

  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_sent = 0;
  u8 n_batch_left;
  u8 n_last_batch_size;
  int err;

  struct xsk_info *xsk = ad->xsk;
  struct xdp_uqueue *uq = &xsk->tx;
  struct xdp_desc *r = uq->ring;

  while (n_left >= BATCH_SIZE)
    {
      if (PREDICT_TRUE (xq_nb_free (uq, BATCH_SIZE) >= BATCH_SIZE))
	{
	  n_batch_left = BATCH_SIZE;
	  while (n_batch_left)
	    {
	      u32 len;
	      u32 offset = 0;
	      vlib_buffer_t *b0;
	      n_batch_left--;
	      u32 bi = buffers[0];
	      buffers++;

	      u32 idx = uq->cached_prod++ & DEFAULT_TX_RING_MASK;
	      u8 *pkt = xq_get_data (xsk, r[idx].addr);

	      do
		{
		  b0 = vlib_get_buffer (vm, bi);
		  len = b0->current_length;
		  clib_memcpy_fast (pkt + offset,
				    vlib_buffer_get_current (b0), len);
		  offset += len;
		}
	      while ((bi = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
		      b0->next_buffer : 0));

	      r[idx].len = offset;	/// rename offset, check for sizes bigger than FRAME_SIZE
	    }
	  n_left -= BATCH_SIZE;

	  u_smp_wmb ();

	  *uq->producer = uq->cached_prod;
	  xsk->outstanding_tx += BATCH_SIZE;
	}
      else
	goto txring_overrun_err;

      if (PREDICT_FALSE (err = complete_tx (xsk, BATCH_SIZE)))
	{
	  vlib_error_count (vm, node->node_index,
			    unix_error_is_fatal (err) ?
			    AF_XDP_TX_ERROR_TXRING_FATAL :
			    AF_XDP_TX_ERROR_TXRING_EAGAIN, BATCH_SIZE);
	  continue;
	}
      n_sent += BATCH_SIZE;
    }

  n_last_batch_size = n_left;
  while (n_left)
    {
      if (PREDICT_TRUE
	  (xq_nb_free (uq, n_last_batch_size) >= n_last_batch_size))
	{
	  n_batch_left = n_left;
	  while (n_batch_left)
	    {
	      u32 len;
	      u32 offset = 0;
	      vlib_buffer_t *b0;
	      n_batch_left--;
	      u32 bi = buffers[0];
	      buffers++;

	      u32 idx = uq->cached_prod++ & DEFAULT_TX_RING_MASK;
	      u8 *pkt = xq_get_data (xsk, r[idx].addr);

	      do
		{
		  b0 = vlib_get_buffer (vm, bi);
		  len = b0->current_length;
		  clib_memcpy_fast (pkt + offset,
				    vlib_buffer_get_current (b0), len);
		  offset += len;
		}
	      while ((bi = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
		      b0->next_buffer : 0));

	      r[idx].len = offset;
	    }
	  n_left -= n_last_batch_size;

	  u_smp_wmb ();

	  *uq->producer = uq->cached_prod;
	  xsk->outstanding_tx += n_last_batch_size;
	}
      else
	goto txring_overrun_err;

      if (PREDICT_FALSE (err = complete_tx (xsk, n_last_batch_size)))
	{
	  vlib_error_count (vm, node->node_index,
			    unix_error_is_fatal (err) ?
			    AF_XDP_TX_ERROR_TXRING_FATAL :
			    AF_XDP_TX_ERROR_TXRING_EAGAIN, n_last_batch_size);
	  continue;
	}
      n_sent += n_last_batch_size;
    }

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return n_sent;

txring_overrun_err:

  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_TXRING_OVERRUN,
		    n_left);
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return n_sent;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_xdp_device_class,) =
{
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AF_XDP_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
af_xdp_init (vlib_main_t * vm)
{
  af_xdp_main_t *am = &af_xdp_main;

  /// move to interface creation
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate_aligned (am->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  am->log_class = vlib_log_register_class ("af_xdp", 0);
  vlib_log_debug (am->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
