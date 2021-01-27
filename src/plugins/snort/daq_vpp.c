
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>

#include "daq_dlt.h"
#include <daq_module_api.h>

#include "daq_vpp.h"

#define DAQ_VPP_VERSION 1

static DAQ_VariableDesc_t afpacket_variable_descriptions[] = {
  { "debug", "Enable debugging output to stdout",
    DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;

#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf (modinst, __VA_ARGS__)

typedef struct _vpp_msg_pool
{
  DAQ_MsgPoolInfo_t info;
} VPPMsgPool;

typedef struct _vpp_desc_data
{
  uint32_t index;
  uint32_t qpair_index;
  DAQ_Msg_t msg;
  DAQ_PktHdr_t pkthdr;
} VPPDescData;

typedef struct _vpp_bpool
{
  int fd;
  uint32_t size;
  void *base;
} VPPBufferPool;

typedef struct _vpp_qpair
{
  uint8_t log2_queue_size;
  daq_vpp_desc_t *descs;
  uint32_t *enq_ring;
  uint32_t *deq_ring;
  volatile uint32_t *enq_head;
  volatile uint32_t *deq_head;
  uint32_t next;
  int enq_fd;
  int deq_fd;
  VPPDescData *desc_data;
} VPPQueuePair;

typedef struct _vpp_context
{
  /* config */
  bool debug;

  /* state */
  uint32_t intf_count;
  DAQ_ModuleInstance_h modinst;
  VPPMsgPool pool;

  /* socket */
  int sock_fd;

  /* shared memory */
  uint32_t shm_size;
  void *shm_base;
  int shm_fd;

  /* queue pairs */
  uint8_t num_qpairs;
  VPPQueuePair *qpairs;

  /* buffer pools */
  uint8_t num_bpools;
  VPPBufferPool *bpools;
} VPP_Context_t;

static int
vpp_daq_module_load (const DAQ_BaseAPI_t *base_api)
{
  if (base_api->api_version != DAQ_BASE_API_VERSION ||
      base_api->api_size != sizeof (DAQ_BaseAPI_t))
    return DAQ_ERROR;

  daq_base_api = *base_api;

  return DAQ_SUCCESS;
}

static int
vpp_daq_module_unload (void)
{
  memset (&daq_base_api, 0, sizeof (daq_base_api));
  return DAQ_SUCCESS;
}

static int
vpp_daq_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
  *var_desc_table = afpacket_variable_descriptions;
  fprintf (stderr, "%s\n", __func__);

  return sizeof (afpacket_variable_descriptions) / sizeof (DAQ_VariableDesc_t);
}

static int
vpp_daq_recvmsg (int fd, daq_vpp_msg_t *msg, int n_fds, int *fds)
{
  const int ctl_sz =
    CMSG_SPACE (sizeof (int) * n_fds) + CMSG_SPACE (sizeof (struct ucred));
  char ctl[ctl_sz];
  struct msghdr mh = {};
  struct iovec iov[1];
  struct cmsghdr *cmsg;

  iov[0].iov_base = (void *) msg;
  iov[0].iov_len = sizeof (daq_vpp_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = ctl_sz;

  memset (ctl, 0, ctl_sz);

  int rv;
  if ((rv = recvmsg (fd, &mh, 0)) != sizeof (daq_vpp_msg_t))
    return DAQ_ERROR_NODEV;

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      /* Do nothing */;
	    }
	  else if (cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      memcpy (fds, CMSG_DATA (cmsg), n_fds * sizeof (int));
	    }
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }

  return DAQ_SUCCESS;
}

static void
vpp_daq_destroy (void *handle)
{
  VPP_Context_t *vc = (VPP_Context_t *) handle;
  fprintf (stderr, "%s\n", __func__);

  if (vc->shm_base != MAP_FAILED)
    munmap (vc->shm_base, vc->shm_size);

  if (vc->shm_fd != -1)
    close (vc->shm_fd);

  if (vc->bpools)
    {
      for (int i = 0; i < vc->num_bpools; i++)
	{
	  VPPBufferPool *bp = vc->bpools + i;
	  if (bp->fd != -1)
	    close (bp->fd);
	  if (bp->base && bp->base != MAP_FAILED)
	    munmap (bp->base, bp->size);
	}
      free (vc->bpools);
    }

  if (vc->qpairs)
    {
      for (int i = 0; i < vc->num_qpairs; i++)
	{
	  VPPQueuePair *qp = vc->qpairs + i;
	  if (qp->enq_fd != -1)
	    close (qp->enq_fd);
	  if (qp->deq_fd != -1)
	    close (qp->deq_fd);
	  if (qp->desc_data)
	    free (qp->desc_data);
	}
      free (vc->qpairs);
    }

  close (vc->sock_fd);
  free (vc);
}

#define ERR(rv, ...)                                                          \
  {                                                                           \
    SET_ERROR (modinst, __VA_ARGS__);                                         \
    rval = rv;                                                                \
    goto err;                                                                 \
  }

static int
vpp_daq_instantiate (const DAQ_ModuleConfig_h modcfg,
		     DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
  VPP_Context_t *vc = 0;
  int rval = DAQ_ERROR;
  daq_vpp_msg_t msg;
  struct sockaddr_un sun = { .sun_family = AF_UNIX };
  int i, fd = -1, shm_fd = -1;
  const char *input;
  uint8_t *base;

  input = daq_base_api.config_get_input (modcfg);

  fprintf (stderr, "%s: input %s\n", __func__, input);

  if ((fd = socket (AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    ERR (DAQ_ERROR_NODEV, "%s: Couldn't create socket!", __func__);

  strncpy (sun.sun_path, DAQ_VPP_DEFAULT_SOCKET_FILE,
	   sizeof (sun.sun_path) - 1);

  if (connect (fd, (struct sockaddr *) &sun, sizeof (struct sockaddr_un)) != 0)
    ERR (DAQ_ERROR_NODEV, "%s: Couldn't connect to socket!", __func__);

  /* craft and send connect message */
  msg.type = DAQ_VPP_MSG_TYPE_HELLO;
  snprintf ((char *) &msg.hello.inst_name, DAQ_VPP_INST_NAME_LEN - 1, "%s",
	    input);

  if (send (fd, &msg, sizeof (msg), 0) != sizeof (msg))
    ERR (DAQ_ERROR_NODEV, "%s: Couldn't send connect message!", __func__);

  /* receive config message */
  rval = vpp_daq_recvmsg (fd, &msg, 1, &shm_fd);

  if (rval != DAQ_SUCCESS || msg.type != DAQ_VPP_MSG_TYPE_CONFIG ||
      shm_fd == -1)
    ERR (DAQ_ERROR_NODEV, "%s: Couldn't receive config message!", __func__);

  fprintf (stderr, "%s: config shm_size %u shm_fd %d\n", __func__,
	   msg.config.shm_size, shm_fd);

  vc = calloc (1, sizeof (VPP_Context_t));

  if (!vc)
    ERR (DAQ_ERROR_NOMEM,
	 "%s: Couldn't allocate memory for the new VPP context!", __func__);

  vc->debug = 1;
  vc->modinst = modinst;
  vc->sock_fd = fd;
  vc->intf_count = 1;
  vc->num_bpools = msg.config.num_bpools;
  vc->num_qpairs = msg.config.num_qpairs;
  vc->shm_size = msg.config.shm_size;
  vc->shm_fd = shm_fd;

  vc->bpools = calloc (vc->num_bpools, sizeof (VPPBufferPool));
  vc->qpairs = calloc (vc->num_bpools, sizeof (VPPQueuePair));

  if (vc->bpools == 0 || vc->qpairs == 0)
    ERR (DAQ_ERROR_NOMEM,
	 "%s: Couldn't allocate memory for the new VPP context!", __func__);

  for (i = 0; i < vc->num_bpools; i++)
    vc->bpools[i].fd = -1;

  base =
    mmap (0, vc->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, vc->shm_fd, 0);

  if (base == MAP_FAILED)
    ERR (DAQ_ERROR_NOMEM,
	 "%s: Couldn't map shared memory for the new VPP context!", __func__);

  vc->shm_base = base;

  if (vc->debug)
    {
      printf ("[%s]\n", input);
      printf ("  Shared memory size: %u\n", vc->shm_size);
      printf ("  Number of buffer pools: %u\n", vc->num_bpools);
      printf ("  Number of queue pairs: %u\n", vc->num_qpairs);
    }

  /* receive buffer pools */
  for (int i = 0; i < vc->num_bpools; i++)
    {
      VPPBufferPool *bp = vc->bpools + i;
      rval = vpp_daq_recvmsg (fd, &msg, 1, &bp->fd);
      if (rval != DAQ_SUCCESS || msg.type != DAQ_VPP_MSG_TYPE_BPOOL ||
	  bp->fd == -1)
	ERR (DAQ_ERROR_NODEV,
	     "%s: Failed to receive buffer pool message for the new "
	     "VPP context!",
	     __func__);
      bp->size = msg.bpool.size;
      bp->base = mmap (0, bp->size, PROT_READ, MAP_SHARED, bp->fd, 0);

      if (bp->base == MAP_FAILED)
	ERR (DAQ_ERROR_NOMEM,
	     "%s: Couldn't map shared memory for the new VPP context!",
	     __func__);
      printf ("  Buffer pool %u size: %u\n", i, bp->size);
    }

  /* receive queue pairs */
  for (int i = 0; i < vc->num_qpairs; i++)
    {
      int fds[2] = { -1, -1 };
      uint32_t qsz;
      VPPQueuePair *qp = vc->qpairs + i;
      rval = vpp_daq_recvmsg (fd, &msg, 2, fds);
      if (rval != DAQ_SUCCESS || msg.type != DAQ_VPP_MSG_TYPE_QPAIR ||
	  fds[0] == -1 || fds[1] == -1)
	ERR (DAQ_ERROR_NODEV,
	     "%s: Failed to receive queu pair message for the new "
	     "VPP context!",
	     __func__);
      qp->log2_queue_size = msg.qpair.log2_queue_size;
      qp->descs = (daq_vpp_desc_t *) (base + msg.qpair.desc_table_offset);
      qp->enq_ring = (uint32_t *) (base + msg.qpair.enq_ring_offset);
      qp->deq_ring = (uint32_t *) (base + msg.qpair.deq_ring_offset);
      qp->enq_head = (uint32_t *) (base + msg.qpair.enq_head_offset);
      qp->deq_head = (uint32_t *) (base + msg.qpair.deq_head_offset);
      qp->enq_fd = fds[0];
      qp->deq_fd = fds[1];
      qsz = 1 << qp->log2_queue_size;

      qp->desc_data = calloc (qsz, sizeof (VPPDescData));
      if (!qp->desc_data)
	ERR (DAQ_ERROR_NOMEM,
	     "%s: Couldn't allocate memory for the new VPP context!",
	     __func__);

      for (int j = 0; j < qsz; j++)
	{
	  VPPDescData *dd = qp->desc_data + j;
	  DAQ_PktHdr_t *pkthdr = &dd->pkthdr;
	  DAQ_Msg_t *msg = &dd->msg;

	  dd->index = j;
	  dd->qpair_index = i;

	  pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
	  pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

	  msg->type = DAQ_MSG_TYPE_PACKET;
	  msg->hdr_len = sizeof (DAQ_PktHdr_t);
	  msg->hdr = pkthdr;
	  msg->owner = vc->modinst;
	  msg->priv = dd;
	}

      printf ("  Queue pair %u:\n", i);
      printf ("    Size: %u\n", 1 << qp->log2_queue_size);
      printf ("    Enqueue fd: %u\n", qp->enq_fd);
      printf ("    Dequeue fd: %u\n", qp->deq_fd);
    }

  *ctxt_ptr = vc;
  return DAQ_SUCCESS;
err:
  if (vc)
    vpp_daq_destroy (vc);
  else if (fd != -1)
    close (fd);
  return rval;
}

static int
vpp_daq_start (void *handle)
{
  fprintf (stderr, "%s\n", __func__);
  return DAQ_SUCCESS;
}

static int
vpp_daq_get_stats (void *handle, DAQ_Stats_t *stats)
{
  fprintf (stderr, "%s\n", __func__);
  memset (stats, 0, sizeof (DAQ_Stats_t));
  return DAQ_SUCCESS;
}

static void
vpp_daq_reset_stats (void *handle)
{
  fprintf (stderr, "%s\n", __func__);
}

static int
vpp_daq_get_datalink_type (void *handle)
{
  return DLT_IPV4;
}

static unsigned
vpp_daq_msg_receive (void *handle, const unsigned max_recv,
		     const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
  VPP_Context_t *vc = (VPP_Context_t *) handle;
  fprintf (stderr, "%s: max_recv  %u\n", __func__, max_recv);
  for (int i = 0; i < vc->num_qpairs; i++)
    {
      uint32_t index;
      daq_vpp_desc_t *d;
      VPPQueuePair *qp = vc->qpairs + i;
      VPPDescData *dd;
      uint32_t mask = (1 << qp->log2_queue_size) - 1;
      uint8_t *data;

      if (*qp->enq_head == qp->next)
	continue;
      index = qp->enq_ring[qp->next];
      qp->next = (qp->next + 1) & mask;
      printf ("qpair %u head %u index %u\n", i, qp->next, index);

      d = qp->descs + index;
      dd = qp->desc_data + index;
      printf ("desc buffer_pool %u offset %u len %u\n", d->buffer_pool,
	      d->offset, d->length);
      data = vc->bpools[d->buffer_pool].base + d->offset;
      printf ("data: %02x%02x%02x%02x\n", data[0], data[1], data[2], data[3]);

      dd->pkthdr.pktlen = d->length;
      dd->msg.data = data;

      msgs[0] = &dd->msg;

      *rstat = DAQ_RSTAT_OK;
      return 1;
    }
  return 0;
}

static int
vpp_daq_msg_finalize (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
  VPP_Context_t *vc = (VPP_Context_t *) handle;
  VPPDescData *dd = msg->priv;
  VPPQueuePair *qp = vc->qpairs + dd->qpair_index;
  daq_vpp_desc_t *d = qp->descs + dd->index;
  uint32_t head = *qp->deq_head;

  char *verdicts[MAX_DAQ_VERDICT] = {
    [DAQ_VERDICT_PASS] = "PASS",
    [DAQ_VERDICT_BLOCK] = "BLOCK",
    [DAQ_VERDICT_REPLACE] = "REPLACE",
    [DAQ_VERDICT_WHITELIST] = "WHITELIST",
    [DAQ_VERDICT_BLACKLIST] = "BLACKLIST",
    [DAQ_VERDICT_IGNORE] = "IGNORE",
    [DAQ_VERDICT_RETRY] = "RETRY",
  };
  fprintf (stderr, "%s: qpair %u slot %u verdict %s\n", __func__,
	   dd->qpair_index, dd->index, verdicts[verdict]);
  d->verdict = verdict;
  qp->deq_ring[head] = dd->index;
  head = (head + 1) & ((1 << qp->log2_queue_size) - 1);
  __atomic_store_n (qp->deq_head, head, __ATOMIC_RELEASE);

  return DAQ_SUCCESS;
}

static int
vpp_daq_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
  VPP_Context_t *vc = (VPP_Context_t *) handle;

  vc->pool.info.available = 1;
  vc->pool.info.size = 256;

  *info = vc->pool.info;

  return DAQ_SUCCESS;
}

DAQ_SO_PUBLIC
const DAQ_ModuleAPI_t DAQ_MODULE_DATA = {
  /* .api_version = */ DAQ_MODULE_API_VERSION,
  /* .api_size = */ sizeof (DAQ_ModuleAPI_t),
  /* .module_version = */ DAQ_VPP_VERSION,
  /* .name = */ "vpp",
  /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE |
    DAQ_TYPE_MULTI_INSTANCE,
  /* .load = */ vpp_daq_module_load,
  /* .unload = */ vpp_daq_module_unload,
  /* .get_variable_descs = */ vpp_daq_get_variable_descs,
  /* .instantiate = */ vpp_daq_instantiate,
  /* .destroy = */ vpp_daq_destroy,
  /* .set_filter = */ NULL,
  /* .start = */ vpp_daq_start,
  /* .inject = */ NULL,
  /* .inject_relative = */ NULL,
  /* .interrupt = */ NULL,
  /* .stop = */ NULL,
  /* .ioctl = */ NULL,
  /* .get_stats = */ vpp_daq_get_stats,
  /* .reset_stats = */ vpp_daq_reset_stats,
  /* .get_snaplen = */ NULL,
  /* .get_capabilities = */ NULL,
  /* .get_datalink_type = */ vpp_daq_get_datalink_type,
  /* .config_load = */ NULL,
  /* .config_swap = */ NULL,
  /* .config_free = */ NULL,
  /* .msg_receive = */ vpp_daq_msg_receive,
  /* .msg_finalize = */ vpp_daq_msg_finalize,
  /* .get_msg_pool_info = */ vpp_daq_get_msg_pool_info,
};
