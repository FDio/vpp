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

#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <bpf/libbpf.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/linux/netns.h>
#include <vppinfra/linux/sysfs.h>
#include <vppinfra/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include "af_xdp.h"

af_xdp_main_t af_xdp_main;

typedef struct
{
  u32 prod;
  u32 cons;
} gdb_af_xdp_pair_t;

gdb_af_xdp_pair_t
gdb_af_xdp_get_prod (const struct xsk_ring_prod *prod)
{
  gdb_af_xdp_pair_t pair = { *prod->producer, *prod->consumer };
  return pair;
}

gdb_af_xdp_pair_t
gdb_af_xdp_get_cons (const struct xsk_ring_cons * cons)
{
  gdb_af_xdp_pair_t pair = { *cons->producer, *cons->consumer };
  return pair;
}

static clib_error_t *
af_xdp_mac_change (vnet_hw_interface_t * hw, const u8 * old, const u8 * new)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  errno_t err = memcpy_s (ad->hwaddr, sizeof (ad->hwaddr), new, 6);
  if (err)
    return clib_error_return_code (0, -err, CLIB_ERROR_ERRNO_VALID,
				   "mac change failed");
  return 0;
}

static clib_error_t *
af_xdp_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hw,
			   u32 frame_size)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "set mtu not supported yet");
  return vnet_error (VNET_ERR_UNSUPPORTED, 0);
}

static u32
af_xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);

  switch (flags)
    {
    case 0:
      af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "set unicast not supported yet");
      return ~0;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      af_xdp_log (VLIB_LOG_LEVEL_ERR, ad,
		  "set promiscuous not supported yet");
      return ~0;
    }

  af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "unknown flag %x requested", flags);
  return ~0;
}

int
af_xdp_enter_netns (char *netns, int *fds)
{
  *fds = *(fds + 1) = -1;
  if (netns != NULL)
    {
      *fds = clib_netns_open (NULL /* self */);
      if ((*(fds + 1) = clib_netns_open ((u8 *) netns)) == -1)
	return VNET_API_ERROR_SYSCALL_ERROR_8;
      if (clib_setns (*(fds + 1)) == -1)
	return VNET_API_ERROR_SYSCALL_ERROR_9;
    }
  return 0;
}

void
af_xdp_cleanup_netns (int *fds)
{
  if (*fds != -1)
    close (*fds);

  if (*(fds + 1) != -1)
    close (*(fds + 1));

  *fds = *(fds + 1) = -1;
}

int
af_xdp_exit_netns (char *netns, int *fds)
{
  int ret = 0;
  if (netns != NULL)
    {
      if (*fds != -1)
	ret = clib_setns (*fds);

      af_xdp_cleanup_netns (fds);
    }

  return ret;
}

void
af_xdp_delete_if (vlib_main_t * vm, af_xdp_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *axm = &af_xdp_main;
  struct xsk_socket **xsk;
  struct xsk_umem **umem;
  int i;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  for (i = 0; i < ad->txq_num; i++)
    clib_spinlock_free (&vec_elt (ad->txqs, i).lock);

  vec_foreach (xsk, ad->xsk)
    xsk_socket__delete (*xsk);

  vec_foreach (umem, ad->umem)
    xsk_umem__delete (*umem);

  for (i = 0; i < ad->rxq_num; i++)
    clib_file_del_by_index (&file_main, vec_elt (ad->rxqs, i).file_index);

  if (ad->bpf_obj)
    {
      int ns_fds[2];
      af_xdp_enter_netns (ad->netns, ns_fds);
      bpf_set_link_xdp_fd (ad->linux_ifindex, -1, 0);
      af_xdp_exit_netns (ad->netns, ns_fds);

      bpf_object__unload (ad->bpf_obj);
    }

  vec_free (ad->xsk);
  vec_free (ad->umem);
  vec_free (ad->buffer_template);
  vec_free (ad->rxqs);
  vec_free (ad->txqs);
  vec_free (ad->name);
  vec_free (ad->linux_ifname);
  vec_free (ad->netns);
  clib_error_free (ad->error);
  pool_put (axm->devices, ad);
}

static int
af_xdp_load_program (af_xdp_create_if_args_t * args, af_xdp_device_t * ad)
{
  int fd;

  ad->linux_ifindex = if_nametoindex (ad->linux_ifname);
  if (!ad->linux_ifindex)
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return_unix (0, "if_nametoindex(%s) failed",
				ad->linux_ifname);
      goto err0;
    }

  if (bpf_prog_load (args->prog, BPF_PROG_TYPE_XDP, &ad->bpf_obj, &fd))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error =
	clib_error_return_unix (0, "bpf_prog_load(%s) failed", args->prog);
      goto err0;
    }

#ifndef XDP_FLAGS_REPLACE
#define XDP_FLAGS_REPLACE 0
#endif
  if (bpf_set_link_xdp_fd (ad->linux_ifindex, fd, XDP_FLAGS_REPLACE))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_6;
      args->error =
	clib_error_return_unix (0, "bpf_set_link_xdp_fd(%s) failed",
				ad->linux_ifname);
      goto err1;
    }

  return 0;

err1:
  bpf_object__unload (ad->bpf_obj);
  ad->bpf_obj = 0;
err0:
  ad->linux_ifindex = ~0;
  return -1;
}

static int
af_xdp_create_queue (vlib_main_t *vm, af_xdp_create_if_args_t *args,
		     af_xdp_device_t *ad, int qid)
{
  struct xsk_umem **umem;
  struct xsk_socket **xsk;
  af_xdp_rxq_t *rxq;
  af_xdp_txq_t *txq;
  struct xsk_umem_config umem_config;
  struct xsk_socket_config sock_config;
  struct xdp_options opt;
  socklen_t optlen;
  const int is_rx = qid < ad->rxq_num;
  const int is_tx = qid < ad->txq_num;

  umem = vec_elt_at_index (ad->umem, qid);
  xsk = vec_elt_at_index (ad->xsk, qid);
  rxq = vec_elt_at_index (ad->rxqs, qid);
  txq = vec_elt_at_index (ad->txqs, qid);

  /*
   * fq and cq must always be allocated even if unused
   * whereas rx and tx indicates whether we want rxq, txq, or both
   */
  struct xsk_ring_cons *rx = is_rx ? &rxq->rx : 0;
  struct xsk_ring_prod *fq = &rxq->fq;
  struct xsk_ring_prod *tx = is_tx ? &txq->tx : 0;
  struct xsk_ring_cons *cq = &txq->cq;
  int fd;

  memset (&umem_config, 0, sizeof (umem_config));
  umem_config.fill_size = args->rxq_size;
  umem_config.comp_size = args->txq_size;
  umem_config.frame_size =
    sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (vm);
  umem_config.frame_headroom = sizeof (vlib_buffer_t);
  umem_config.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
  if (xsk_umem__create
      (umem, uword_to_pointer (vm->buffer_main->buffer_mem_start, void *),
       vm->buffer_main->buffer_mem_size, fq, cq, &umem_config))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return_unix (0, "xsk_umem__create() failed");
      goto err0;
    }

  memset (&sock_config, 0, sizeof (sock_config));
  sock_config.rx_size = args->rxq_size;
  sock_config.tx_size = args->txq_size;
  sock_config.bind_flags = XDP_USE_NEED_WAKEUP;
  switch (args->mode)
    {
    case AF_XDP_MODE_AUTO:
      break;
    case AF_XDP_MODE_COPY:
      sock_config.bind_flags |= XDP_COPY;
      break;
    case AF_XDP_MODE_ZERO_COPY:
      sock_config.bind_flags |= XDP_ZEROCOPY;
      break;
    }
  if (xsk_socket__create
      (xsk, ad->linux_ifname, qid, *umem, rx, tx, &sock_config))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error =
	clib_error_return_unix (0,
				"xsk_socket__create() failed (is linux netdev %s up?)",
				ad->linux_ifname);
      goto err1;
    }

  fd = xsk_socket__fd (*xsk);
  optlen = sizeof (opt);
  if (getsockopt (fd, SOL_XDP, XDP_OPTIONS, &opt, &optlen))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      args->error =
	clib_error_return_unix (0, "getsockopt(XDP_OPTIONS) failed");
      goto err2;
    }
  if (opt.flags & XDP_OPTIONS_ZEROCOPY)
    ad->flags |= AF_XDP_DEVICE_F_ZEROCOPY;

  rxq->xsk_fd = is_rx ? fd : -1;

  if (is_tx)
    {
      txq->xsk_fd = fd;
      clib_spinlock_init (&txq->lock);
      if (is_rx && (ad->flags & AF_XDP_DEVICE_F_SYSCALL_LOCK))
	{
	  /* This is a shared rx+tx queue and we need to lock before syscalls.
	   * Prior to Linux 5.6 there is a race condition preventing to call
	   * poll() and sendto() concurrently on AF_XDP sockets. This was
	   * fixed with commit 11cc2d21499cabe7e7964389634ed1de3ee91d33
	   * to workaround this issue, we protect the syscalls with a
	   * spinlock. Note that it also prevents to use interrupt mode in
	   * multi workers setup, because in this case the poll() is done in
	   * the framework w/o any possibility to protect it.
	   * See
	   * https://lore.kernel.org/bpf/BYAPR11MB365382C5DB1E5FCC53242609C1549@BYAPR11MB3653.namprd11.prod.outlook.com/
	   */
	  clib_spinlock_init (&rxq->syscall_lock);
	  txq->syscall_lock = rxq->syscall_lock;
	}
    }
  else
    {
      txq->xsk_fd = -1;
    }

  return 0;

err2:
  xsk_socket__delete (*xsk);
err1:
  xsk_umem__delete (*umem);
err0:
  *umem = 0;
  *xsk = 0;
  return -1;
}

static int
af_xdp_get_numa (const char *ifname)
{
  char *path;
  clib_error_t *err;
  int numa;

  path =
    (char *) format (0, "/sys/class/net/%s/device/numa_node%c", ifname, 0);
  err = clib_sysfs_read (path, "%d", &numa);
  if (err || numa < 0)
    numa = 0;

  clib_error_free (err);
  vec_free (path);
  return numa;
}

static void
af_xdp_get_q_count (const char *ifname, int *rxq_num, int *txq_num)
{
  struct ethtool_channels ec = { .cmd = ETHTOOL_GCHANNELS };
  struct ifreq ifr = { .ifr_data = (void *) &ec };
  int fd, err;

  *rxq_num = *txq_num = 1;

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return;

  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ifname);
  err = ioctl (fd, SIOCETHTOOL, &ifr);

  close (fd);

  if (err)
    return;

  *rxq_num = clib_max (ec.combined_count, ec.rx_count);
  *txq_num = clib_max (ec.combined_count, ec.tx_count);
}

static clib_error_t *
af_xdp_device_rxq_read_ready (clib_file_t * f)
{
  vnet_hw_if_rx_queue_set_int_pending (vnet_get_main (), f->private_data);
  return 0;
}

static clib_error_t *
af_xdp_device_set_rxq_mode (const af_xdp_device_t *ad, af_xdp_rxq_t *rxq,
			    const af_xdp_rxq_mode_t mode)
{
  clib_file_main_t *fm = &file_main;
  clib_file_update_type_t update;
  clib_file_t *f;

  if (rxq->mode == mode)
    return 0;

  switch (mode)
    {
    case AF_XDP_RXQ_MODE_POLLING:
      update = UNIX_FILE_UPDATE_DELETE;
      break;
    case AF_XDP_RXQ_MODE_INTERRUPT:
      if (ad->flags & AF_XDP_DEVICE_F_SYSCALL_LOCK)
	return clib_error_create (
	  "kernel workaround incompatible with interrupt mode");
      update = UNIX_FILE_UPDATE_ADD;
      break;
    default:
      ASSERT (0);
      return clib_error_create ("unknown rxq mode %i", mode);
    }

  f = clib_file_get (fm, rxq->file_index);
  fm->file_update (f, update);
  rxq->mode = mode;
  return 0;
}

static u32
af_xdp_find_rxq_for_thread (vnet_main_t *vnm, const af_xdp_device_t *ad,
			    const u32 thread)
{
  u32 i;
  for (i = 0; i < ad->rxq_num; i++)
    {
      const u32 qid = vec_elt (ad->rxqs, i).queue_index;
      const u32 tid = vnet_hw_if_get_rx_queue (vnm, qid)->thread_index;
      if (tid == thread)
	return i;
    }
  return ~0;
}

static clib_error_t *
af_xdp_finalize_queues (vnet_main_t *vnm, af_xdp_device_t *ad,
			const int n_vlib_mains)
{
  clib_error_t *err = 0;
  int i;

  for (i = 0; i < ad->rxq_num; i++)
    {
      af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
      rxq->queue_index = vnet_hw_if_register_rx_queue (
	vnm, ad->hw_if_index, i, VNET_HW_IF_RXQ_THREAD_ANY);
      u8 *desc = format (0, "%U rxq %d", format_af_xdp_device_name,
			 ad->dev_instance, i);
      clib_file_t f = {
	.file_descriptor = rxq->xsk_fd,
	.private_data = rxq->queue_index,
	.read_function = af_xdp_device_rxq_read_ready,
	.description = desc,
      };
      rxq->file_index = clib_file_add (&file_main, &f);
      vnet_hw_if_set_rx_queue_file_index (vnm, rxq->queue_index,
					  rxq->file_index);
      err = af_xdp_device_set_rxq_mode (ad, rxq, AF_XDP_RXQ_MODE_POLLING);
      if (err)
	return err;
    }

  for (i = 0; i < ad->txq_num; i++)
    vec_elt (ad->txqs, i).queue_index =
      vnet_hw_if_register_tx_queue (vnm, ad->hw_if_index, i);

  /* We set the rxq and txq of the same queue pair on the same thread
   * by default to avoid locking because of the syscall lock. */
  int last_qid = clib_min (ad->rxq_num, ad->txq_num - 1);
  for (i = 0; i < n_vlib_mains; i++)
    {
      /* search for the 1st rxq assigned on this thread, if any */
      u32 qid = af_xdp_find_rxq_for_thread (vnm, ad, i);
      /* if this rxq is combined with a txq, use it. Otherwise, we'll
       * assign txq in a round-robin fashion. We start from the 1st txq
       * not shared with a rxq if possible... */
      qid = qid < ad->txq_num ? qid : (last_qid++ % ad->txq_num);
      vnet_hw_if_tx_queue_assign_thread (
	vnm, vec_elt (ad->txqs, qid).queue_index, i);
    }

  vnet_hw_if_update_runtime_data (vnm, ad->hw_if_index);
  return 0;
}

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_eth_interface_registration_t eir = {};
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  vnet_sw_interface_t *sw;
  int rxq_num, txq_num, q_num;
  int ns_fds[2];
  int i, ret;

  args->rxq_size = args->rxq_size ? args->rxq_size : 2 * VLIB_FRAME_SIZE;
  args->txq_size = args->txq_size ? args->txq_size : 2 * VLIB_FRAME_SIZE;
  args->rxq_num = args->rxq_num ? args->rxq_num : 1;

  if (!args->linux_ifname)
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (0, "missing host interface");
      goto err0;
    }

  if (args->rxq_size < VLIB_FRAME_SIZE || args->txq_size < VLIB_FRAME_SIZE ||
      args->rxq_size > 65535 || args->txq_size > 65535 ||
      !is_pow2 (args->rxq_size) || !is_pow2 (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (0,
			   "queue size must be a power of two between %i and 65535",
			   VLIB_FRAME_SIZE);
      goto err0;
    }

  ret = af_xdp_enter_netns (args->netns, ns_fds);
  if (ret)
    {
      args->rv = ret;
      args->error = clib_error_return (0, "enter netns %s failed, ret %d",
				       args->netns, args->rv);
      goto err0;
    }

  af_xdp_get_q_count (args->linux_ifname, &rxq_num, &txq_num);
  if (args->rxq_num > rxq_num && AF_XDP_NUM_RX_QUEUES_ALL != args->rxq_num)
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_create ("too many rxq requested (%d > %d)",
				       args->rxq_num, rxq_num);
      goto err1;
    }
  rxq_num = clib_min (rxq_num, args->rxq_num);
  txq_num = clib_min (txq_num, tm->n_vlib_mains);

  pool_get_zero (am->devices, ad);

  if (tm->n_vlib_mains > 1 &&
      0 == (args->flags & AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK))
    ad->flags |= AF_XDP_DEVICE_F_SYSCALL_LOCK;

  ad->linux_ifname = (char *) format (0, "%s", args->linux_ifname);
  vec_validate (ad->linux_ifname, IFNAMSIZ - 1);	/* libbpf expects ifname to be at least IFNAMSIZ */

  ad->netns = (char *) format (0, "%s", args->netns);

  if (args->prog && af_xdp_load_program (args, ad))
    goto err2;

  q_num = clib_max (rxq_num, txq_num);
  ad->rxq_num = rxq_num;
  ad->txq_num = txq_num;

  vec_validate_aligned (ad->umem, q_num - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ad->xsk, q_num - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ad->rxqs, q_num - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ad->txqs, q_num - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < q_num; i++)
    {
      if (af_xdp_create_queue (vm, args, ad, i))
	{
	  /*
	   * queue creation failed
	   * it is only a fatal error if we could not create the number of rx
	   * queues requested explicitely by the user and the user did not
	   * requested 'max'
	   * we might create less tx queues than workers but this is ok
	   */
	  af_xdp_log (VLIB_LOG_LEVEL_DEBUG, ad,
		      "create interface failed to create queue qid=%d", i);

	  /* fixup vectors length */
	  vec_set_len (ad->umem, i);
	  vec_set_len (ad->xsk, i);
	  vec_set_len (ad->rxqs, i);
	  vec_set_len (ad->txqs, i);

	  ad->rxq_num = clib_min (i, rxq_num);
	  ad->txq_num = clib_min (i, txq_num);

	  if (i == 0 ||
	      (i < rxq_num && AF_XDP_NUM_RX_QUEUES_ALL != args->rxq_num))
	    {
	      ad->rxq_num = ad->txq_num = 0;
	      goto err2; /* failed creating requested rxq: fatal error, bailing
			    out */
	    }


	  args->rv = 0;
	  clib_error_free (args->error);
	  break;
	}
    }

  if (af_xdp_exit_netns (args->netns, ns_fds))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_10;
      args->error = clib_error_return (0, "exit netns failed");
      goto err2;
    }

  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  ad->pool =
    vlib_buffer_pool_get_default_for_numa (vm,
					   af_xdp_get_numa
					   (ad->linux_ifname));
  if (!args->name)
    {
      char *ifname = ad->linux_ifname;
      if (args->netns != NULL && strncmp (args->netns, "pid:", 4) == 0)
	{
	  ad->name =
	    (char *) format (0, "%s/%u", ifname, atoi (args->netns + 4));
	}
      else
	ad->name = (char *) format (0, "%s/%d", ifname, ad->dev_instance);
    }
  else
    ad->name = (char *) format (0, "%s", args->name);

  ethernet_mac_address_generate (ad->hwaddr);

  /* create interface */
  eir.dev_class_index = af_xdp_device_class.index;
  eir.dev_instance = ad->dev_instance;
  eir.address = ad->hwaddr;
  eir.cb.flag_change = af_xdp_flag_change;
  eir.cb.set_max_frame_size = af_xdp_set_max_frame_size;
  ad->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_if_set_caps (vnm, ad->hw_if_index, VNET_HW_IF_CAP_INT_MODE);

  vnet_hw_if_set_input_node (vnm, ad->hw_if_index, af_xdp_input_node.index);

  args->error = af_xdp_finalize_queues (vnm, ad, tm->n_vlib_mains);
  if (args->error)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      goto err2;
    }

  /* buffer template */
  vec_validate_aligned (ad->buffer_template, 1, CLIB_CACHE_LINE_BYTES);
  ad->buffer_template->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
  ad->buffer_template->ref_count = 1;
  vnet_buffer (ad->buffer_template)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (ad->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  ad->buffer_template->buffer_pool_index = ad->pool;

  return;

err2:
  af_xdp_delete_if (vm, ad);
err1:
  af_xdp_cleanup_netns (ns_fds);
err0:
  vlib_log_err (am->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
af_xdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & AF_XDP_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= AF_XDP_DEVICE_F_ADMIN_UP;
      af_xdp_device_input_refill (ad);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~AF_XDP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
af_xdp_interface_rx_mode_change (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
				 vnet_hw_if_rx_mode mode)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);
  af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  switch (mode)
    {
    default:			     /* fallthrough */
    case VNET_HW_IF_RX_MODE_UNKNOWN: /* fallthrough */
    case VNET_HW_IF_NUM_RX_MODES:
      return clib_error_create ("uknown rx mode - doing nothing");
    case VNET_HW_IF_RX_MODE_DEFAULT: /* fallthrough */
    case VNET_HW_IF_RX_MODE_POLLING:
      return af_xdp_device_set_rxq_mode (ad, rxq, AF_XDP_RXQ_MODE_POLLING);
    case VNET_HW_IF_RX_MODE_INTERRUPT: /* fallthrough */
    case VNET_HW_IF_RX_MODE_ADAPTIVE:
      return af_xdp_device_set_rxq_mode (ad, rxq, AF_XDP_RXQ_MODE_INTERRUPT);
    }

  ASSERT (0 && "unreachable");
  return clib_error_create ("unreachable");
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

static void
af_xdp_clear (u32 dev_instance)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, dev_instance);
  clib_error_free (ad->error);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_xdp_device_class) = {
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_mode_change_function = af_xdp_interface_rx_mode_change,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AF_XDP_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
  .mac_addr_change_function = af_xdp_mac_change,
  .clear_counters = af_xdp_clear,
};
/* *INDENT-ON* */

clib_error_t *
af_xdp_init (vlib_main_t * vm)
{
  af_xdp_main_t *am = &af_xdp_main;

  am->log_class = vlib_log_register_class ("af_xdp", 0);

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
