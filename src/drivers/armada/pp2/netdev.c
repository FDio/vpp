/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <dirent.h>
#include <errno.h>
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

#define MVPP2_NETDEV_FEATURE_STRINGS_MAX 64
#define MVPP2_NETDEV_COMMAND_SIZE	 256

typedef struct
{
  char *strings[MVPP2_NETDEV_FEATURE_STRINGS_MAX];
} mvpp2_netdev_feature_strings_t;

static void *
mvpp2_netdev_calloc (size_t count, size_t size)
{
  size_t bytes;
  void *p;

  if (__builtin_mul_overflow (count, size, &bytes))
    return 0;

  p = clib_mem_alloc (bytes);
  clib_memset (p, 0, bytes);
  return p;
}

static vnet_dev_rv_t
mvpp2_netdev_feature_strings_get (vnet_dev_t *dev, int fd, struct ifreq *ifr,
				  mvpp2_netdev_feature_strings_t *feature_strings)
{
  struct ethtool_sset_info *sset_cmd;
  struct ethtool_gstrings *gstrs;
  int32_t len;
  char *s;
  int i, ret;

  sset_cmd = mvpp2_netdev_calloc (1, sizeof (*sset_cmd) + sizeof (sset_cmd->data[0]));
  sset_cmd->cmd = ETHTOOL_GSSET_INFO;
  sset_cmd->sset_mask = 1 << ETH_SS_FEATURES;

  ifr->ifr_data = (char *) sset_cmd;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature count (%s)", strerror (errno));
      clib_mem_free (sset_cmd);
      return VNET_DEV_ERR_INTERNAL;
    }

  clib_memcpy (&len, sset_cmd->data, sizeof (len));
  clib_mem_free (sset_cmd);
  if (len < 0 || len > MVPP2_NETDEV_FEATURE_STRINGS_MAX)
    {
      log_err (dev, "invalid feature count %d", len);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  gstrs = mvpp2_netdev_calloc (1, sizeof (*gstrs) + len * ETH_GSTRING_LEN);
  gstrs->cmd = ETHTOOL_GSTRINGS;
  gstrs->string_set = ETH_SS_FEATURES;
  gstrs->len = len;

  ifr->ifr_data = (char *) gstrs;
  ret = ioctl (fd, SIOCETHTOOL, ifr);
  if (ret)
    {
      log_err (dev, "Could not get feature strings (%s)", strerror (errno));
      clib_mem_free (gstrs);
      return VNET_DEV_ERR_INTERNAL;
    }

  s = (char *) gstrs->data;
  for (i = 0; i < len; i++)
    {
      s[ETH_GSTRING_LEN - 1] = 0;
      feature_strings->strings[i] = clib_mem_alloc (strlen (s) + 1);
      strcpy (feature_strings->strings[i], s);
      s += ETH_GSTRING_LEN;
    }
  clib_mem_free (gstrs);
  return VNET_DEV_OK;
}

static void
mvpp2_netdev_feature_strings_free (mvpp2_netdev_feature_strings_t *feature_strings)
{
  int i;

  for (i = 0; i < MVPP2_NETDEV_FEATURE_STRINGS_MAX; i++)
    {
      if (feature_strings->strings[i] == 0)
	continue;
      clib_mem_free (feature_strings->strings[i]);
      feature_strings->strings[i] = 0;
    }
}

static vnet_dev_rv_t
mvpp2_netdev_feature_ioctl (vnet_dev_t *dev, int fd, struct ifreq *ifr, int bit, int val)
{
  struct ethtool_sfeatures *cmd;
  int word = bit / 32;
  int sbit = bit % 32;
  int ret;

  cmd = mvpp2_netdev_calloc (1, sizeof (*cmd) + 2 * sizeof (cmd->features[0]));
  cmd->cmd = ETHTOOL_SFEATURES;
  cmd->size = 2;
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
      clib_mem_free (cmd);
      return VNET_DEV_ERR_INTERNAL;
    }

  clib_mem_free (cmd);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mvpp2_netdev_feature_set (vnet_dev_t *dev, const char *netdev, const char *feature, int val)
{
  mvpp2_netdev_feature_strings_t feature_strings = {};
  struct ifreq ifr = {};
  vnet_dev_rv_t rv;
  int feature_bit;
  int fd;
  int i;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return VNET_DEV_ERR_INTERNAL;
    }

  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", netdev);
  rv = mvpp2_netdev_feature_strings_get (dev, fd, &ifr, &feature_strings);
  if (rv != VNET_DEV_OK)
    goto done;

  for (i = 0; i < MVPP2_NETDEV_FEATURE_STRINGS_MAX; i++)
    if (feature_strings.strings[i] && strcmp (feature_strings.strings[i], feature) == 0)
      break;

  if (i == MVPP2_NETDEV_FEATURE_STRINGS_MAX)
    {
      log_err (dev, "failed to find feature %s", feature);
      rv = VNET_DEV_ERR_NOT_FOUND;
      goto done;
    }

  feature_bit = i;
  rv = mvpp2_netdev_feature_ioctl (dev, fd, &ifr, feature_bit, !!val);

done:
  close (fd);
  mvpp2_netdev_feature_strings_free (&feature_strings);
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

vnet_dev_rv_t
mvpp2_netdev_clear_kernel_unicast (vnet_dev_port_t *port)
{
  char command[MVPP2_NETDEV_COMMAND_SIZE], full_name[32];
  char ifname[IFNAMSIZ];
  char name[IFNAMSIZ];
  struct dirent *dent;
  DIR *dir;
  u8 id;

  dir = opendir ("/sys/class/net/");
  if (!dir)
    return VNET_DEV_ERR_NOT_FOUND;
  mvpp2_port_ifname (port, ifname);

  while ((dent = readdir (dir)))
    {
      if (!strcmp (dent->d_name, ".") || !strcmp (dent->d_name, ".."))
	continue;
      if (sscanf (dent->d_name, "%[^.].%02hhu", name, &id) != 2)
	continue;
      if (strcmp (ifname, name))
	continue;

      snprintf (full_name, sizeof (full_name), "%s.%u", name, id);
      snprintf (command, sizeof (command), "ip -d link show %s | grep macvlan", full_name);
      if (system (command) == 0)
	/* mac interface found */
	/* same function can be used to remove macvlan interface */
	mvpp2_netdev_clear_vlan (port, id);
    }

  closedir (dir);
  return VNET_DEV_OK;
}
