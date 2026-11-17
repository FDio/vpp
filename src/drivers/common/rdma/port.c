/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vppinfra/clib.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/pci/pci.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <infiniband/verbs.h>
#include <rdma/common.h>

enum
{
  RDMA_IB_SPEED_SDR = 1,
  RDMA_IB_SPEED_DDR = 2,
  RDMA_IB_SPEED_QDR = 4,
  RDMA_IB_SPEED_FDR10 = 8,
  RDMA_IB_SPEED_FDR = 16,
  RDMA_IB_SPEED_EDR = 32,
  RDMA_IB_SPEED_HDR = 64,
  RDMA_IB_SPEED_NDR = 128,
  RDMA_IB_SPEED_XDR = 256,
};

enum
{
  RDMA_IB_WIDTH_1X = 1,
  RDMA_IB_WIDTH_4X = 2,
  RDMA_IB_WIDTH_8X = 4,
  RDMA_IB_WIDTH_12X = 8,
  RDMA_IB_WIDTH_2X = 16,
};

u32
rdma_port_speed (struct ibv_port_attr *attr)
{
  u32 speed = attr->active_speed ? attr->active_speed : attr->active_speed_ex;
  u32 lane, width;

  switch (speed)
    {
    case RDMA_IB_SPEED_SDR:
      lane = 2500000;
      break;
    case RDMA_IB_SPEED_DDR:
      lane = 5000000;
      break;
    case RDMA_IB_SPEED_QDR:
    case RDMA_IB_SPEED_FDR10:
      lane = 10000000;
      break;
    case RDMA_IB_SPEED_FDR:
      lane = 14000000;
      break;
    case RDMA_IB_SPEED_EDR:
      lane = 25000000;
      break;
    case RDMA_IB_SPEED_HDR:
      lane = 50000000;
      break;
    case RDMA_IB_SPEED_NDR:
      lane = 100000000;
      break;
    case RDMA_IB_SPEED_XDR:
      lane = 200000000;
      break;
    default:
      return 0;
    }

  switch (attr->active_width)
    {
    case RDMA_IB_WIDTH_1X:
      width = 1;
      break;
    case RDMA_IB_WIDTH_2X:
      width = 2;
      break;
    case RDMA_IB_WIDTH_4X:
      width = 4;
      break;
    case RDMA_IB_WIDTH_8X:
      width = 8;
      break;
    case RDMA_IB_WIDTH_12X:
      width = 12;
      break;
    default:
      return 0;
    }

  return lane * width;
}

u32
rdma_port_netdev_ifindex (vlib_pci_addr_t *addr, u8 ibv_port)
{
  u8 *path = format (0, "/sys/bus/pci/devices/%U/net%c", format_vlib_pci_addr, addr, 0);
  struct dirent *e;
  u32 ifindex = 0;
  DIR *dir;

  dir = opendir ((char *) path);
  if (dir == 0)
    goto done;

  while (ifindex == 0 && (e = readdir (dir)))
    {
      u32 dev_port;

      if (e->d_name[0] == '.')
	continue;

      vec_reset_length (path);
      path = format (path, "/sys/bus/pci/devices/%U/net/%s/dev_port%c", format_vlib_pci_addr, addr,
		     e->d_name, 0);
      if (clib_sysfs_read ((char *) path, "%u", &dev_port) == 0 && dev_port + 1 == ibv_port)
	ifindex = if_nametoindex (e->d_name);
    }

  closedir (dir);
done:
  vec_free (path);
  return ifindex;
}

void
rdma_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port, struct ibv_context *ctx)
{
  struct ibv_port_attr port_attr = {};
  vnet_dev_port_state_changes_t changes = {};
  u8 link_up;
  u32 speed;

  if (ibv_query_port (ctx, port->port_id, &port_attr))
    return;

  link_up = port_attr.state == IBV_PORT_ACTIVE;
  speed = link_up ? rdma_port_speed (&port_attr) : 0;

  if (port->link_up != link_up)
    {
      changes.change.link_state = 1;
      changes.link_state = link_up;
    }

  if (port->speed != speed)
    {
      changes.change.link_speed = 1;
      changes.link_speed = speed;
    }

  if (changes.change.any)
    vnet_dev_port_state_change (vm, port, changes);
}

int
rdma_qp_start (struct ibv_qp *qp, u8 ibv_port, rdma_qp_stage_t *failed_stage)
{
  struct ibv_qp_attr qpa = {};
  int rv_ibv;

  if (failed_stage)
    *failed_stage = RDMA_QP_STAGE_NONE;

  if (qp == 0)
    return EINVAL;

  qpa.qp_state = IBV_QPS_RESET;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RESET;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_INIT;
  qpa.port_num = ibv_port;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE | IBV_QP_PORT);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_INIT;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_RTR;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RTR;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_RTS;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RTS;
      return rv_ibv;
    }

  return 0;
}

int
rdma_qp_stop (struct ibv_qp *qp)
{
  if (qp == 0)
    return EINVAL;

  return ibv_modify_qp (qp,
			&(struct ibv_qp_attr) {
			  .qp_state = IBV_QPS_RESET,
			},
			IBV_QP_STATE);
}

void
rdma_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			 vnet_dev_hw_addr_t **addrs)
{
  vnet_dev_hw_addr_t addr = port->primary_hw_addr;
  vnet_dev_hw_addr_t *a;

  if (req && req->type == VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR)
    addr = req->addr;

  vec_add1 (*addrs, addr);

  pool_foreach (a, port->secondary_hw_addr)
    {
      if (req && req->type == VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR)
	{
	  if (clib_memcmp (a, &req->addr, sizeof (*a)) == 0)
	    continue;
	}
      vec_add1 (*addrs, *a);
    }

  if (req && req->type == VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR)
    vec_add1 (*addrs, req->addr);
}

vnet_dev_rv_t
rdma_port_cfg_rxq_intr_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid, u8 enable,
				    u8 all, rdma_rxq_irq_enable_fn_t *rxq_irq_enable,
				    rdma_rxq_irq_disable_fn_t *rxq_irq_disable)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (port->started == 0)
    return rv;

  if (all)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  if (rxq->started == 0)
	    continue;
	  if (enable)
	    rv = rxq_irq_enable (vm, rxq);
	  else
	    rxq_irq_disable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }
  else
    {
      vnet_dev_rx_queue_t *rxq = vnet_dev_get_port_rx_queue_by_id (port, qid);
      if (rxq == 0)
	return VNET_DEV_ERR_BUG;
      if (rxq->started == 0)
	return rv;
      if (enable)
	rv = rxq_irq_enable (vm, rxq);
      else
	rxq_irq_disable (vm, rxq);
    }

  return rv;
}

static int
rdma_netdev_ethtool (int fd, char *ifname, void *data)
{
  struct ifreq ifr = { .ifr_data = data };

  strncpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name) - 1);
  return ioctl (fd, SIOCETHTOOL, &ifr);
}

vnet_dev_rv_t
rdma_netdev_module_eeprom_read (u32 ifindex, vnet_dev_port_module_eeprom_req_t *r)
{
  struct ethtool_modinfo mi = { .cmd = ETHTOOL_GMODULEINFO };
  u8 buf[sizeof (struct ethtool_eeprom) + 256] __clib_aligned (8)
  = {};
  struct ethtool_eeprom *ee = (struct ethtool_eeprom *) buf;
  char ifname[IF_NAMESIZE];
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 off;
  int fd;

  if (r->bank || ifindex == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (r->offset + r->length > 256)
    return VNET_DEV_ERR_INVALID_ARG;

  if (if_indextoname (ifindex, ifname) == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    return VNET_DEV_ERR_INTERNAL;

  if (rdma_netdev_ethtool (fd, ifname, &mi) < 0)
    {
      rv = errno == EOPNOTSUPP ? VNET_DEV_ERR_NOT_SUPPORTED : VNET_DEV_ERR_NOT_READY;
      goto done;
    }

  if (r->i2c_address == 0x51 && r->page == 0 && mi.type == ETH_MODULE_SFF_8472)
    off = 256 + r->offset;
  else if (r->i2c_address == 0x50 && r->page == 0)
    off = r->offset;
  else if (r->i2c_address == 0x50 && r->offset >= 128 &&
	   (mi.type == ETH_MODULE_SFF_8436 || mi.type == ETH_MODULE_SFF_8636))
    off = 256 + (r->page - 1) * 128 + r->offset - 128;
  else
    {
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      goto done;
    }

  if (off + r->length > mi.eeprom_len)
    {
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      goto done;
    }

  ee->cmd = ETHTOOL_GMODULEEEPROM;
  ee->offset = off;
  ee->len = r->length;
  if (rdma_netdev_ethtool (fd, ifname, ee) < 0)
    {
      rv = VNET_DEV_ERR_NOT_READY;
      goto done;
    }

  clib_memcpy (r->data, ee->data, r->length);

done:
  close (fd);
  return rv;
}

static int
rdma_gid_to_mac (const union ibv_gid *gid, u8 *mac)
{
  const u8 *raw = gid->raw;

  if (raw[11] != 0xff || raw[12] != 0xfe)
    return 0;

  mac[0] = raw[8] ^ 0x02;
  mac[1] = raw[9];
  mac[2] = raw[10];
  mac[3] = raw[13];
  mac[4] = raw[14];
  mac[5] = raw[15];
  return 1;
}

int
rdma_port_mac (struct ibv_context *ctx, u8 ibv_port, int gid_tbl_len, vnet_dev_hw_addr_t *hw_addr)
{
  struct ibv_gid_entry gid_entry = {};
  u8 mac[6];

  for (int gid_index = 0; gid_index < gid_tbl_len; gid_index++)
    {
      if (ibv_query_gid_ex (ctx, ibv_port, gid_index, &gid_entry, 0))
	continue;
      if (gid_entry.gid_type != IBV_GID_TYPE_ROCE_V1 && gid_entry.gid_type != IBV_GID_TYPE_ROCE_V2)
	continue;
      if (!rdma_gid_to_mac (&gid_entry.gid, mac))
	continue;
      vnet_dev_set_hw_addr_eth_mac (hw_addr, mac);
      return 1;
    }

  return 0;
}

uword
rdma_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr)
{
  unformat_input_t in;
  uword rv;
  u8 *s;

  s = clib_file_get_resolved_basename ("%s", path);
  if (!s)
    return 0;

  unformat_init_string (&in, (char *) s, strlen ((char *) s));
  rv = unformat (&in, "%U", unformat_vlib_pci_addr, addr);
  unformat_free (&in);
  vec_free (s);
  return rv;
}

static struct ibv_device *
rdma_find_device (struct ibv_device **list, int n, vlib_pci_addr_t *addr)
{
  struct ibv_device *d = 0;
  u8 *path = 0;

  for (int i = 0; i < n && d == 0; i++)
    {
      vlib_pci_addr_t a;

      vec_reset_length (path);
      path = format (path, "%s/device%c", list[i]->dev_path, 0);
      if (rdma_sysfs_path_to_pci_addr ((char *) path, &a) && a.as_u32 == addr->as_u32)
	d = list[i];
    }

  vec_free (path);
  return d;
}

int
rdma_pci_addr_has_device (vlib_pci_addr_t *addr)
{
  struct ibv_device **list;
  int n = 0, found;

  list = ibv_get_device_list (&n);
  if (list == 0)
    return 0;
  found = rdma_find_device (list, n, addr) != 0;
  ibv_free_device_list (list);
  return found;
}

vnet_dev_rv_t
rdma_open_device (vlib_pci_addr_t *addr, struct ibv_context **ctxp)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_device **list, *d;
  int n = 0;

  list = ibv_get_device_list (&n);
  if (list == 0 || n <= 0)
    rv = VNET_DEV_ERR_NOT_READY;
  else if ((d = rdma_find_device (list, n, addr)) == 0)
    rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  else if ((*ctxp = ibv_open_device (d)) == 0)
    rv = VNET_DEV_ERR_BUS;

  if (list)
    ibv_free_device_list (list);
  return rv;
}

int
rdma_dev_close (struct ibv_context *ctx, struct ibv_pd *pd, struct ibv_mr *mr)
{
  int rv = 0, r;

  if (mr && (r = ibv_dereg_mr (mr)) && rv == 0)
    rv = r;
  if (pd && (r = ibv_dealloc_pd (pd)) && rv == 0)
    rv = r;
  if (ctx && (r = ibv_close_device (ctx)) && rv == 0)
    rv = r;
  return rv;
}
