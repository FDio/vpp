/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phylink.h>
#include <linux/phy.h>
#include <linux/rtnetlink.h>

#include "kdi_internal.h"

static struct kdi_ethernet_phy *
kdi_ethernet_phy_from_config (struct phylink_config *config)
{
  return container_of (config, struct kdi_ethernet_phy, config);
}

static void
kdi_ethernet_phy_mac_config (struct phylink_config *config, unsigned int mode,
			     const struct phylink_link_state *state)
{
  struct kdi_ethernet_phy *ethernet_phy = kdi_ethernet_phy_from_config (config);

  kdi_dbg (
    ethernet_phy->dev,
    "phylink requests MAC mode %u, interface %s; MAC and PCS registers are configured by VPP\n",
    mode, phy_modes (state->interface));
}

static void
kdi_ethernet_phy_link_down (struct phylink_config *config, unsigned int mode,
			    phy_interface_t interface)
{
  struct kdi_ethernet_phy *ethernet_phy = kdi_ethernet_phy_from_config (config);
  unsigned long flags;

  spin_lock_irqsave (&ethernet_phy->state_lock, flags);
  ethernet_phy->state.link = 0;
  ethernet_phy->state.speed = 0;
  spin_unlock_irqrestore (&ethernet_phy->state_lock, flags);
}

static void
kdi_ethernet_phy_link_up (struct phylink_config *config, struct phy_device *phy, unsigned int mode,
			  phy_interface_t interface, int speed, int duplex, bool tx_pause,
			  bool rx_pause)
{
  struct kdi_ethernet_phy *ethernet_phy = kdi_ethernet_phy_from_config (config);
  unsigned long flags;

  spin_lock_irqsave (&ethernet_phy->state_lock, flags);
  ethernet_phy->state = (struct kdi_ethernet_phy_state) {
    .link = speed > 0,
    .speed = speed > 0 ? speed : 0,
    .duplex = duplex == DUPLEX_FULL,
    .autoneg = phy ? phy->autoneg == AUTONEG_ENABLE : mode == MLO_AN_INBAND,
  };
  spin_unlock_irqrestore (&ethernet_phy->state_lock, flags);
  kdi_dbg (ethernet_phy->dev, "phylink reports link up: interface %s, speed %d Mbps, duplex %s\n",
	   phy_modes (interface), speed, duplex == DUPLEX_FULL ? "full" : "half");
}

static const struct phylink_mac_ops kdi_ethernet_phy_mac_ops = {
  .mac_config = kdi_ethernet_phy_mac_config,
  .mac_link_down = kdi_ethernet_phy_link_down,
  .mac_link_up = kdi_ethernet_phy_link_up,
};

static int
kdi_ethernet_phy_open (struct kdi_resource *resource)
{
  struct kdi_ethernet_phy *ethernet_phy;
  const char *netdev_name;
  phy_interface_t interface;
  int ret;

  ret = of_get_phy_mode (resource->node, &interface);
  if (ret)
    return ret;

  ethernet_phy = kzalloc (sizeof (*ethernet_phy), GFP_KERNEL);
  if (!ethernet_phy)
    return -ENOMEM;

  spin_lock_init (&ethernet_phy->state_lock);
  ethernet_phy->state = (struct kdi_ethernet_phy_state) { .autoneg = 1 };

  ethernet_phy->dev = resource->dev;
  /* Keep NETREG_UNINITIALIZED so carrier changes do not queue linkwatch work
   * for this private phylink/SFP device. */
  ethernet_phy->netdev = alloc_etherdev (0);
  if (!ethernet_phy->netdev)
    {
      kfree (ethernet_phy);
      return -ENOMEM;
    }
  if (of_property_read_string (resource->node, "label", &netdev_name))
    netdev_name = resource->node->name;
  strscpy (ethernet_phy->netdev->name, netdev_name, IFNAMSIZ);
  SET_NETDEV_DEV (ethernet_phy->netdev, resource->dev);

  ethernet_phy->config.dev = &ethernet_phy->netdev->dev;
  ethernet_phy->config.type = PHYLINK_NETDEV;
  ethernet_phy->config.mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE | MAC_10 | MAC_100 |
					  MAC_1000 | MAC_2500FD | MAC_5000FD | MAC_10000FD;
  __set_bit (interface, ethernet_phy->config.supported_interfaces);

  ethernet_phy->phylink = phylink_create (&ethernet_phy->config, of_fwnode_handle (resource->node),
					  interface, &kdi_ethernet_phy_mac_ops);
  if (IS_ERR (ethernet_phy->phylink))
    {
      ret = PTR_ERR (ethernet_phy->phylink);
      goto error_free_netdev;
    }

  ret = phylink_of_phy_connect (ethernet_phy->phylink, resource->node, 0);
  if (ret)
    goto error_destroy_phylink;

  resource->resource.ethernet_phy = ethernet_phy;
  kdi_dbg (resource->dev, "opened phylink for port node '%pOF': interface %s, PHY connected\n",
	   resource->node, phy_modes (interface));
  return 0;

error_destroy_phylink:
  phylink_destroy (ethernet_phy->phylink);
error_free_netdev:
  free_netdev (ethernet_phy->netdev);
  kfree (ethernet_phy);
  return ret;
}

static void
kdi_ethernet_phy_release (struct kdi_resource *resource)
{
  struct kdi_ethernet_phy *ethernet_phy = resource->resource.ethernet_phy;

  if (!ethernet_phy)
    return;
  mutex_lock (&resource->lock);
  if (ethernet_phy->started)
    {
      rtnl_lock ();
      phylink_stop (ethernet_phy->phylink);
      rtnl_unlock ();
      ethernet_phy->started = false;
    }
  rtnl_lock ();
  phylink_disconnect_phy (ethernet_phy->phylink);
  rtnl_unlock ();
  mutex_unlock (&resource->lock);
  phylink_destroy (ethernet_phy->phylink);
  free_netdev (ethernet_phy->netdev);
  kfree (ethernet_phy);
  resource->resource.ethernet_phy = NULL;
  kdi_dbg (resource->dev, "released phylink resource for port node '%pOF'\n", resource->node);
}

static long
kdi_ethernet_phy_ioctl (struct kdi_resource *resource, unsigned int cmd, void __user *argp)
{
  struct kdi_ethernet_phy *ethernet_phy = resource->resource.ethernet_phy;
  struct kdi_ethernet_phy_state state;
  unsigned long flags;

  switch (cmd)
    {
    case KDI_IOC_ETHERNET_PHY_START_ANEG:
      mutex_lock (&resource->lock);
      if (!ethernet_phy->started)
	{
	  rtnl_lock ();
	  phylink_start (ethernet_phy->phylink);
	  rtnl_unlock ();
	  ethernet_phy->started = true;
	}
      mutex_unlock (&resource->lock);
      kdi_dbg (resource->dev, "started phylink autonegotiation for port node '%pOF'\n",
	       resource->node);
      return 0;
    case KDI_IOC_ETHERNET_PHY_STOP:
      mutex_lock (&resource->lock);
      if (ethernet_phy->started)
	{
	  rtnl_lock ();
	  phylink_stop (ethernet_phy->phylink);
	  rtnl_unlock ();
	  ethernet_phy->started = false;
	}
      mutex_unlock (&resource->lock);
      kdi_dbg (resource->dev, "stopped phylink for port node '%pOF'\n", resource->node);
      return 0;
    case KDI_IOC_ETHERNET_PHY_GET_STATE:
      spin_lock_irqsave (&ethernet_phy->state_lock, flags);
      state = ethernet_phy->state;
      spin_unlock_irqrestore (&ethernet_phy->state_lock, flags);
      kdi_dbg (
	resource->dev,
	"phylink state for port node '%pOF': link %u, speed %u Mbps, duplex %s, autoneg %u\n",
	resource->node, state.link, state.speed, state.duplex ? "full" : "half", state.autoneg);
      return copy_to_user (argp, &state, sizeof (state)) ? -EFAULT : 0;
    default:
      return -ENOTTY;
    }
}

static long
kdi_ethernet_phy_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_ethernet_phy_ioctl (file->private_data, cmd, (void __user *) arg);
}

static int
kdi_ethernet_phy_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_ethernet_phy_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_ethernet_phy_fops = {
  .owner = THIS_MODULE,
  .release = kdi_ethernet_phy_file_release,
  .unlocked_ioctl = kdi_ethernet_phy_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_ethernet_phy_resource_type = {
  .open = kdi_ethernet_phy_open,
  .release = kdi_ethernet_phy_release,
  .fops = &kdi_ethernet_phy_fops,
};
