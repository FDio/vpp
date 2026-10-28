/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/overflow.h>
#include <linux/slab.h>

#include "kdi_internal.h"

static struct kdi_clk *
to_kdi_clk (struct clk_hw *hw)
{
  return container_of (hw, struct kdi_clk, hw);
}

/* Forwards one clk_ops call to whichever userspace process holds the
 * resource open, and blocks until it answers via KDI_IOC_CLOCK_PROVIDER_
 * COMPLETE or a fixed timeout elapses. kdi never interprets op or rate
 * itself; it is purely a transport between the clk framework and
 * userspace. */
static int
kdi_clock_provider_request (struct kdi_clk *clk, enum kdi_clock_provider_op op, u64 rate,
			     u64 *out_rate)
{
  struct kdi_clock_provider *provider = clk->provider;
  long wait_ret;
  int ret;

  mutex_lock (&provider->resource->lock);
  provider->request = (struct kdi_clock_provider_request) {
    .index = clk->index,
    .op = op,
    .rate = rate,
  };
  provider->response_ready = false;
  provider->request_pending = true;
  provider->request_delivered = false;
  mutex_unlock (&provider->resource->lock);

  wait_ret = wait_event_interruptible_timeout (provider->response_wq, provider->response_ready,
						5 * HZ);
  if (wait_ret == 0)
    return -ETIMEDOUT;
  if (wait_ret < 0)
    return wait_ret;

  mutex_lock (&provider->resource->lock);
  ret = provider->response.result;
  if (!ret && out_rate)
    *out_rate = provider->response.rate;
  provider->response_ready = false;
  mutex_unlock (&provider->resource->lock);
  return ret;
}

static int
kdi_clk_prepare (struct clk_hw *hw)
{
  struct kdi_clk *clk = to_kdi_clk (hw);
  u64 rate = clk->rate;
  int ret = kdi_clock_provider_request (clk, KDI_CLOCK_PROVIDER_OP_PREPARE, rate, &rate);

  if (ret)
    return ret;
  clk->prepared = true;
  clk->rate = rate;
  return 0;
}

static void
kdi_clk_unprepare (struct clk_hw *hw)
{
  struct kdi_clk *clk = to_kdi_clk (hw);

  kdi_clock_provider_request (clk, KDI_CLOCK_PROVIDER_OP_UNPREPARE, 0, NULL);
  clk->prepared = false;
}

static int
kdi_clk_is_prepared (struct clk_hw *hw)
{
  return to_kdi_clk (hw)->prepared;
}

static int
kdi_clk_set_rate (struct clk_hw *hw, unsigned long rate, unsigned long parent_rate)
{
  struct kdi_clk *clk = to_kdi_clk (hw);
  u64 actual = rate;
  int ret;

  if (clk->self_push)
    {
      clk->rate = rate;
      return 0;
    }

  ret = kdi_clock_provider_request (clk, KDI_CLOCK_PROVIDER_OP_SET_RATE, rate, &actual);
  if (ret)
    return ret;
  clk->rate = actual;
  return 0;
}

static unsigned long
kdi_clk_recalc_rate (struct clk_hw *hw, unsigned long parent_rate)
{
  /* Never blocks: recalc_rate can be called from contexts that must not
   * sleep, so it only ever reports the last rate a prepare/set_rate round
   * trip to userspace actually confirmed. */
  return to_kdi_clk (hw)->rate;
}

static long
kdi_clk_round_rate (struct clk_hw *hw, unsigned long rate, unsigned long *parent_rate)
{
  return rate;
}

static const struct clk_ops kdi_clk_ops = {
  .prepare = kdi_clk_prepare,
  .unprepare = kdi_clk_unprepare,
  .is_prepared = kdi_clk_is_prepared,
  .set_rate = kdi_clk_set_rate,
  .recalc_rate = kdi_clk_recalc_rate,
  .round_rate = kdi_clk_round_rate,
};

static int
kdi_clock_provider_open (struct kdi_resource *resource)
{
  struct kdi_clock_provider *provider;
  unsigned int n_clks = resource->arg;
  unsigned int i;
  int ret;

  if (!n_clks || n_clks > 16)
    return -EINVAL;

  provider = kzalloc (sizeof (*provider), GFP_KERNEL);
  if (!provider)
    return -ENOMEM;

  provider->clks = kcalloc (n_clks, sizeof (*provider->clks), GFP_KERNEL);
  provider->onecell = kzalloc (struct_size (provider->onecell, hws, n_clks), GFP_KERNEL);
  if (!provider->clks || !provider->onecell)
    {
      ret = -ENOMEM;
      goto error_free_provider;
    }

  provider->resource = resource;
  provider->node = resource->node;
  init_waitqueue_head (&provider->response_wq);

  for (i = 0; i < n_clks; i++)
    {
      char name[KDI_RESOURCE_NAME_LEN];
      struct clk_init_data init = { .ops = &kdi_clk_ops };

      snprintf (name, sizeof (name), "%pOFn.%u", resource->node, i);
      init.name = name;

      provider->clks[i].provider = provider;
      provider->clks[i].index = i;
      provider->clks[i].hw.init = &init;
      ret = clk_hw_register (resource->dev, &provider->clks[i].hw);
      if (ret)
	goto error_unregister;
      provider->onecell->hws[i] = &provider->clks[i].hw;
    }
  provider->n_clks = n_clks;
  provider->onecell->num = n_clks;

  ret = of_clk_add_hw_provider (resource->node, of_clk_hw_onecell_get, provider->onecell);
  if (ret)
    goto error_unregister;

  resource->resource.clock_provider = provider;
  kdi_dbg (resource->dev, "registered clock provider for node '%pOF' with %u output(s)\n",
	   resource->node, n_clks);
  return 0;

error_unregister:
  while (i-- > 0)
    clk_hw_unregister (&provider->clks[i].hw);
error_free_provider:
  kfree (provider->onecell);
  kfree (provider->clks);
  kfree (provider);
  return ret;
}

static void
kdi_clock_provider_release (struct kdi_resource *resource)
{
  struct kdi_clock_provider *provider = resource->resource.clock_provider;

  of_clk_del_provider (provider->node);
  for (unsigned int i = 0; i < provider->n_clks; i++)
    clk_hw_unregister (&provider->clks[i].hw);
  kdi_dbg (resource->dev, "released clock provider for node '%pOF'\n", resource->node);
  kfree (provider->onecell);
  kfree (provider->clks);
  kfree (provider);
}

static long
kdi_clock_provider_ioctl (struct kdi_resource *resource, unsigned int cmd, void __user *argp)
{
  struct kdi_clock_provider *provider = resource->resource.clock_provider;
  struct kdi_clock_provider_request request;
  struct kdi_clock_provider_response response;
  struct kdi_clock_provider_notify_rate notify;
  struct clk *clk;
  struct kdi_clk *kclk;
  int ret;

  switch (cmd)
    {
    case KDI_IOC_CLOCK_PROVIDER_NOTIFY_RATE:
      if (copy_from_user (&notify, argp, sizeof (notify)))
	return -EFAULT;
      if (notify.index >= provider->n_clks)
	return -EINVAL;
      kclk = &provider->clks[notify.index];
      clk = clk_hw_get_clk (&kclk->hw, "kdi-notify-rate");
      if (IS_ERR (clk))
	return PTR_ERR (clk);
      kclk->self_push = true;
      ret = clk_set_rate (clk, notify.rate);
      kclk->self_push = false;
      clk_put (clk);
      kdi_dbg (resource->dev, "clock provider notify-rate: index %u rate %llu: result %d\n",
	       notify.index, notify.rate, ret);
      return ret;
    case KDI_IOC_CLOCK_PROVIDER_WAIT_REQUEST:
      /* Non-blocking: qppe polls this periodically from its own per-port
       * poll callback rather than parking a dataplane thread in the
       * kernel. -EAGAIN just means there is nothing to service right now. */
      mutex_lock (&resource->lock);
      if (!provider->request_pending || provider->request_delivered)
	{
	  mutex_unlock (&resource->lock);
	  return -EAGAIN;
	}
      request = provider->request;
      provider->request_delivered = true;
      mutex_unlock (&resource->lock);
      return copy_to_user (argp, &request, sizeof (request)) ? -EFAULT : 0;
    case KDI_IOC_CLOCK_PROVIDER_COMPLETE:
      if (copy_from_user (&response, argp, sizeof (response)))
	return -EFAULT;
      mutex_lock (&resource->lock);
      provider->response = response;
      provider->request_pending = false;
      provider->request_delivered = false;
      provider->response_ready = true;
      mutex_unlock (&resource->lock);
      wake_up (&provider->response_wq);
      return 0;
    default:
      return -ENOTTY;
    }
}

static long
kdi_clock_provider_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_clock_provider_ioctl (file->private_data, cmd, (void __user *) arg);
}

static int
kdi_clock_provider_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_clock_provider_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_clock_provider_fops = {
  .owner = THIS_MODULE,
  .release = kdi_clock_provider_file_release,
  .unlocked_ioctl = kdi_clock_provider_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_clock_provider_resource_type = {
  .open = kdi_clock_provider_open,
  .release = kdi_clock_provider_release,
  .fops = &kdi_clock_provider_fops,
};
