/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "netdev",
};

#define MVPP2_NETDEV_COMMAND_SIZE 256

static vnet_dev_rv_t
mvpp2_netdev_feature_get_bit (vnet_dev_t *dev, int fd, struct ifreq *ifr, const char *feature,
			      int *feature_bit, u32 *n_features)
{
  u8 *sset_data = 0;
  u8 *gstrs_data = 0;
  struct ethtool_sset_info *sset_cmd;
  struct ethtool_gstrings *gstrs;
  u32 len;
  char *s;
  int ret;
  uword size;

  size = sizeof (*sset_cmd) + sizeof (sset_cmd->data[0]);
  vec_validate (sset_data, size - 1);
  sset_cmd = (void *) sset_data;
  sset_cmd->cmd = ETHTOOL_GSSET_INFO;
  sset_cmd->sset_mask = 1 << ETH_SS_FEATURES;

  ifr->ifr_data = (char *) sset_cmd;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature count (%s)", strerror (errno));
      vec_free (sset_data);
      return VNET_DEV_ERR_INTERNAL;
    }

  len = sset_cmd->data[0];
  vec_free (sset_data);
  if (len == 0)
    {
      log_err (dev, "invalid feature count %u", len);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  size = sizeof (*gstrs) + len * ETH_GSTRING_LEN;
  vec_validate (gstrs_data, size - 1);
  gstrs = (void *) gstrs_data;
  gstrs->cmd = ETHTOOL_GSTRINGS;
  gstrs->string_set = ETH_SS_FEATURES;
  gstrs->len = len;

  ifr->ifr_data = (char *) gstrs;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature strings (%s)", strerror (errno));
      vec_free (gstrs_data);
      return VNET_DEV_ERR_INTERNAL;
    }

  for (int i = 0; i < len; i++)
    {
      s = (char *) gstrs->data + i * ETH_GSTRING_LEN;
      if (!strncmp (s, feature, ETH_GSTRING_LEN))
	{
	  *feature_bit = i;
	  *n_features = len;
	  vec_free (gstrs_data);
	  return VNET_DEV_OK;
	}
    }
  vec_free (gstrs_data);
  log_err (dev, "failed to find feature %s", feature);
  return VNET_DEV_ERR_NOT_FOUND;
}

static vnet_dev_rv_t
mvpp2_netdev_feature_ioctl (vnet_dev_t *dev, int fd, struct ifreq *ifr, int bit, int val,
			    u32 n_features)
{
  u8 *data = 0;
  struct ethtool_sfeatures *cmd;
  int word = bit / 32;
  int sbit = bit % 32;
  u32 n_words = round_pow2 (n_features, 32) / 32;
  int ret;
  uword size;

  size = sizeof (*cmd) + n_words * sizeof (cmd->features[0]);
  vec_validate (data, size - 1);
  cmd = (void *) data;
  cmd->cmd = ETHTOOL_SFEATURES;
  cmd->size = n_words;
  ifr->ifr_data = (char *) cmd;
  cmd->features[word].valid |= 1 << sbit;
  cmd->features[word].requested = val << sbit;

  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      if (ret < 0)
	log_err (dev, "Error setting bit (%s)", strerror (errno));
      else
	log_err (dev, "Error setting bit (%d)", ret);
      vec_free (data);
      return VNET_DEV_ERR_INTERNAL;
    }

  vec_free (data);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mvpp2_netdev_feature_set (vnet_dev_t *dev, const char *netdev, const char *feature, int val)
{
  struct ifreq ifr = {};
  vnet_dev_rv_t rv;
  u32 n_features;
  int feature_bit;
  int fd;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return VNET_DEV_ERR_INTERNAL;
    }

  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", netdev);
  rv = mvpp2_netdev_feature_get_bit (dev, fd, &ifr, feature, &feature_bit, &n_features);
  if (rv != VNET_DEV_OK)
    goto done;

  rv = mvpp2_netdev_feature_ioctl (dev, fd, &ifr, feature_bit, !!val, n_features);

done:
  close (fd);
  return rv;
}

vnet_dev_rv_t
mvpp2_netdev_ioctl (vnet_dev_t *dev, u32 request, struct ifreq *ifr)
{
  int fd;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return VNET_DEV_ERR_INTERNAL;
    }

  if (ioctl (fd, request, ifr) == -1)
    {
      log_err (dev, "ioctl request failed: errno %d", errno);
      close (fd);
      return VNET_DEV_ERR_INTERNAL;
    }
  close (fd);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_netdev_set_enable (vnet_dev_port_t *port, int enable)
{
  struct ifreq ifr = {};
  vnet_dev_rv_t rv;

  mvpp2_port_ifname (port, ifr.ifr_name);
  log_debug (port->dev, "port %d ifname %s enable %d", port->port_id, ifr.ifr_name, enable);
  rv = mvpp2_netdev_ioctl (port->dev, SIOCGIFFLAGS, &ifr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (enable)
    ifr.ifr_flags |= IFF_UP;
  else
    ifr.ifr_flags &= ~IFF_UP;
  return mvpp2_netdev_ioctl (port->dev, SIOCSIFFLAGS, &ifr);
}

vnet_dev_rv_t
mvpp2_netdev_set_priv_flags (vnet_dev_port_t *port, u32 val)
{
  struct ethtool_value param = {
    .cmd = ETHTOOL_SPFLAGS,
    .data = val,
  };
  struct ifreq ifr = {};

  mvpp2_port_ifname (port, ifr.ifr_name);
  ifr.ifr_data = (char *) &param;
  return mvpp2_netdev_ioctl (port->dev, SIOCETHTOOL, &ifr);
}

vnet_dev_rv_t
mvpp2_netdev_set_vlan_filtering (vnet_dev_port_t *port, int enable)
{
  char ifname[IFNAMSIZ];

  mvpp2_port_ifname (port, ifname);
  return mvpp2_netdev_feature_set (port->dev, ifname, "rx-vlan-filter", enable);
}

vnet_dev_rv_t
mvpp2_netdev_clear_vlan (vnet_dev_port_t *port, u16 vlan)
{
  char command[MVPP2_NETDEV_COMMAND_SIZE];
  char ifname[IFNAMSIZ];

  /* build manually the system command */
  /* [TODO] check other alternatives for setting vlan id */
  mvpp2_port_ifname (port, ifname);
  snprintf (command, sizeof (command), "ip link delete %s.%d", ifname, vlan);
  if (system (command) != 0)
    {
      log_err (port->dev, "clear vlan operation failed");
      return VNET_DEV_ERR_INTERNAL;
    }
  return VNET_DEV_OK;
}
