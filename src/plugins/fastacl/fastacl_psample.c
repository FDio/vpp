/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <fastacl/fastacl.h>
#include <linux/psample.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

static int
fa_nl_resolve_psample (u16 *family_id, u32 *group_id)
{
  struct nl_sock *sk = nl_socket_alloc ();
  int rv = -1;

  if (!sk)
    return -1;
  if (genl_connect (sk))
    goto done;

  int family = genl_ctrl_resolve (sk, FASTACL_PSAMPLE_FAMILY);
  if (family < 0)
    goto done;

  int group = genl_ctrl_resolve_grp (sk, FASTACL_PSAMPLE_FAMILY, FASTACL_PSAMPLE_GROUP);
  if (group < 0 || group > FASTACL_NL_MAX_MCAST_GROUP)
    goto done;

  *family_id = (u16) family;
  *group_id = (u32) group;
  rv = 0;

done:
  nl_socket_free (sk);
  return rv;
}

int
fastacl_psample_init (void)
{
  fastacl_psample_main_t *ps = &fastacl_main.psample;

  if (ps->family_id)
    return 0;

  u16 family_id = 0;
  u32 group_id = 0;

  int rv = fa_nl_resolve_psample (&family_id, &group_id);
  if (rv == 0)
    {
      ps->family_id = family_id;
      ps->group_id = group_id;
    }
  return rv;
}

int
fastacl_psample_worker_open (fastacl_psample_worker_t *w)
{
  fastacl_psample_main_t *ps = &fastacl_main.psample;

  if (w->sk)
    return 0;

  w->sk = nl_socket_alloc ();
  if (!w->sk)
    return -1;
  if (genl_connect (w->sk))
    {
      nl_socket_free (w->sk);
      w->sk = 0;
      return -1;
    }
  nl_socket_disable_auto_ack (w->sk);
  w->family_id = ps->family_id;
  w->group_id = ps->group_id;
  return 0;
}

void
fastacl_psample_worker_close (fastacl_psample_worker_t *w)
{
  if (w->sk)
    {
      nl_socket_free (w->sk);
      w->sk = 0;
    }
}

int
fastacl_psample_send (fastacl_psample_worker_t *w, u32 group, u32 rate, u32 iifindex, u32 origsize,
		      const u8 *data, u32 len)
{
  struct sockaddr_nl dst = { .nl_family = AF_NETLINK, .nl_groups = (1u << (w->group_id - 1)) };
  struct nl_msg *msg = nlmsg_alloc ();
  int rv = -1;

  if (!msg)
    return -1;
  nlmsg_set_dst (msg, &dst);

  if (!genlmsg_put (msg, NL_AUTO_PORT, NL_AUTO_SEQ, w->family_id, 0, 0, PSAMPLE_CMD_SAMPLE,
		    PSAMPLE_GENL_VERSION))
    goto done;
  if (nla_put_u32 (msg, PSAMPLE_ATTR_IIFINDEX, iifindex) ||
      nla_put_u32 (msg, PSAMPLE_ATTR_SAMPLE_RATE, rate) ||
      nla_put_u32 (msg, PSAMPLE_ATTR_ORIGSIZE, origsize) ||
      nla_put_u32 (msg, PSAMPLE_ATTR_SAMPLE_GROUP, group) ||
      nla_put_u32 (msg, PSAMPLE_ATTR_GROUP_SEQ, w->seq++) ||
      nla_put (msg, PSAMPLE_ATTR_DATA, (int) len, data))
    goto done;

  rv = nl_send (w->sk, msg) < 0 ? -1 : 0;

done:
  nlmsg_free (msg);
  return rv;
}
