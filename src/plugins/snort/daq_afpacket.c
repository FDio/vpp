/*
 *
 ** Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2010-2013 Sourcefire, Inc.
 ** Author: Michael R. Altizer <mialtize@cisco.com>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE // For POLLRDHUP

#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef LIBPCAP_AVAILABLE
#include <pcap.h>
#include <pthread.h>
#else
#include "daq_dlt.h"
#endif

#include "daq_module_api.h"

#define DAQ_AFPACKET_VERSION 7

#define AF_PACKET_DEFAULT_BUFFER_SIZE 128
#define AF_PACKET_MAX_INTERFACES      32

#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf (modinst, __VA_ARGS__)

union thdr
{
  struct tpacket2_hdr *h2;
  uint8_t *raw;
};

typedef struct _af_packet_entry
{
  struct _af_packet_entry *next;
  union thdr hdr;
} AFPacketEntry;

typedef struct _af_packet_ring
{
  struct tpacket_req layout;
  unsigned int size;
  void *start;
  AFPacketEntry *entries;
  AFPacketEntry *cursor;
} AFPacketRing;

typedef struct _af_packet_instance
{
  struct _af_packet_instance *next;
  int fd;
  unsigned tp_version;
  unsigned tp_hdrlen;
  unsigned tp_reserve;
  unsigned tp_frame_size;
  unsigned actual_snaplen;
  void *buffer;
  AFPacketRing rx_ring;
  AFPacketRing tx_ring;
  char *name;
  int index;
  struct _af_packet_instance *peer;
  int mtu;
  bool active;
} AFPacketInstance;

typedef struct _af_packet_fanout_cfg
{
  uint16_t fanout_flags;
  uint16_t fanout_type;
  bool enabled;
} AFPacketFanoutCfg;

typedef struct _af_packet_pkt_desc
{
  DAQ_Msg_t msg;
  DAQ_PktHdr_t pkthdr;
  uint8_t *data;
  AFPacketInstance *instance;
  unsigned int length;
  struct _af_packet_pkt_desc *next;
} AFPacketPktDesc;

typedef struct _af_packet_msg_pool
{
  AFPacketPktDesc *pool;
  AFPacketPktDesc *freelist;
  DAQ_MsgPoolInfo_t info;
} AFPacketMsgPool;

typedef struct _afpacket_context
{
  /* Configuration */
  char *device;
  char *filter;
  int snaplen;
  int timeout;
  uint32_t ring_size;
  AFPacketFanoutCfg fanout_cfg;
  bool use_tx_ring;
  bool debug;
  /* State */
  DAQ_ModuleInstance_h modinst;
  AFPacketMsgPool pool;
  AFPacketInstance *instances;
  uint32_t intf_count;
#ifdef LIBPCAP_AVAILABLE
  struct bpf_program fcode;
#endif
  volatile bool interrupted;
  DAQ_Stats_t stats;
  /* Message receive state */
  AFPacketInstance *curr_instance;
} AFPacket_Context_t;

/* VLAN defintions stolen from LibPCAP's vlan.h. */
struct vlan_tag
{
  u_int16_t vlan_tpid; /* ETH_P_8021Q */
  u_int16_t vlan_tci;  /* VLAN TCI */
};
#define VLAN_TAG_LEN 4

static DAQ_VariableDesc_t afpacket_variable_descriptions[] = {
  { "buffer_size_mb", "Packet buffer space to allocate in megabytes",
    DAQ_VAR_DESC_REQUIRES_ARGUMENT },
  { "debug", "Enable debugging output to stdout",
    DAQ_VAR_DESC_FORBIDS_ARGUMENT },
  { "fanout_type", "Fanout loadbalancing method",
    DAQ_VAR_DESC_REQUIRES_ARGUMENT },
  { "fanout_flag", "Fanout loadbalancing option",
    DAQ_VAR_DESC_REQUIRES_ARGUMENT },
  { "use_tx_ring", "Use memory-mapped TX ring",
    DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static const int vlan_offset = 2 * ETH_ALEN;
static DAQ_BaseAPI_t daq_base_api;
#ifdef LIBPCAP_AVAILABLE
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static void
destroy_packet_pool (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketMsgPool *pool = &afpc->pool;
  if (pool->pool)
    {
      while (pool->info.size > 0)
	free (pool->pool[--pool->info.size].data);
      free (pool->pool);
      pool->pool = NULL;
    }
  pool->freelist = NULL;
  pool->info.available = 0;
  pool->info.mem_size = 0;
}

static int
create_packet_pool (AFPacket_Context_t *afpc, unsigned size)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketMsgPool *pool = &afpc->pool;
  pool->pool = calloc (sizeof (AFPacketPktDesc), size);
  if (!pool->pool)
    {
      SET_ERROR (
	afpc->modinst,
	"%s: Could not allocate %zu bytes for a packet descriptor pool!",
	__func__, sizeof (AFPacketPktDesc) * size);
      return DAQ_ERROR_NOMEM;
    }
  pool->info.mem_size = sizeof (AFPacketPktDesc) * size;
  while (pool->info.size < size)
    {
      /* Allocate packet data and set up descriptor */
      AFPacketPktDesc *desc = &pool->pool[pool->info.size];
      desc->data = malloc (afpc->instances->actual_snaplen);
      if (!desc->data)
	{
	  SET_ERROR (afpc->modinst,
		     "%s: Could not allocate %d bytes for a packet descriptor "
		     "message buffer!",
		     __func__, afpc->instances->actual_snaplen);
	  return DAQ_ERROR_NOMEM;
	}
      pool->info.mem_size += afpc->instances->actual_snaplen;

      /* Initialize non-zero invariant packet header fields. */
      DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
      pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
      pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

      /* Initialize non-zero invariant message header fields. */
      DAQ_Msg_t *msg = &desc->msg;
      msg->type = DAQ_MSG_TYPE_PACKET;
      msg->hdr_len = sizeof (desc->pkthdr);
      msg->hdr = &desc->pkthdr;
      msg->data = desc->data;
      msg->owner = afpc->modinst;
      msg->priv = desc;

      /* Place it on the free list */
      desc->next = pool->freelist;
      pool->freelist = desc;

      pool->info.size++;
    }
  pool->info.available = pool->info.size;
  return DAQ_SUCCESS;
}

static int
bind_instance_interface (AFPacket_Context_t *afpc, AFPacketInstance *instance,
			 int protocol)
{
  fprintf (stderr, "func: %s\n", __func__);
  struct sockaddr_ll sll;
  int err;
  socklen_t errlen = sizeof (err);

  /* Bind to the specified device so we only see packets from it. */
  memset (&sll, 0, sizeof (struct sockaddr_ll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = instance->index;
  sll.sll_protocol = htons (protocol);

  if (bind (instance->fd, (struct sockaddr *) &sll, sizeof (sll)) == -1)
    {
      SET_ERROR (afpc->modinst, "%s: bind(%s): %s\n", __func__, instance->name,
		 strerror (errno));
      return DAQ_ERROR;
    }

  /* Any pending errors, e.g., network is down? */
  if (getsockopt (instance->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) || err)
    {
      SET_ERROR (afpc->modinst, "%s: getsockopt: %s", __func__,
		 err ? strerror (err) : strerror (errno));
      return DAQ_ERROR;
    }

  return DAQ_SUCCESS;
}

static int
set_up_ring (AFPacket_Context_t *afpc, AFPacketInstance *instance,
	     AFPacketRing *ring)
{
  fprintf (stderr, "func: %s\n", __func__);
  unsigned int idx, block, frame, frame_offset;

  /* Allocate a ring to hold packet pointers. */
  ring->entries = calloc (ring->layout.tp_frame_nr, sizeof (AFPacketEntry));
  if (!ring->entries)
    {
      SET_ERROR (afpc->modinst,
		 "%s: Could not allocate ring buffer entries for device %s!",
		 __func__, instance->name);
      return DAQ_ERROR_NOMEM;
    }

  /* Set up the buffer entry pointers in the ring. */
  idx = 0;
  for (block = 0; block < ring->layout.tp_block_nr; block++)
    {
      unsigned int block_offset = block * ring->layout.tp_block_size;
      for (frame = 0;
	   frame < (ring->layout.tp_block_size / ring->layout.tp_frame_size) &&
	   idx < ring->layout.tp_frame_nr;
	   frame++)
	{
	  frame_offset = frame * ring->layout.tp_frame_size;
	  ring->entries[idx].hdr.raw =
	    (uint8_t *) ring->start + block_offset + frame_offset;
	  ring->entries[idx].next = &ring->entries[idx + 1];
	  idx++;
	}
    }
  /* Make this a circular buffer ... a RING if you will! */
  ring->entries[ring->layout.tp_frame_nr - 1].next = &ring->entries[0];
  /* Initialize our entry point into the ring as the first buffer entry. */
  ring->cursor = &ring->entries[0];

  return DAQ_SUCCESS;
}

static void
destroy_instance (AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  if (instance)
    {
      if (instance->fd != -1)
	{
	  /* Destroy the userspace RX ring. */
	  if (instance->rx_ring.entries)
	    {
	      free (instance->rx_ring.entries);
	      instance->rx_ring.entries = NULL;
	    }
	  /* Destroy the userspace TX ring. */
	  if (instance->tx_ring.entries)
	    {
	      free (instance->tx_ring.entries);
	      instance->tx_ring.entries = NULL;
	    }
	  /* Unmap the kernel packet ring. */
	  if (instance->buffer != MAP_FAILED)
	    {
	      unsigned int ringsize =
		instance->rx_ring.size + instance->tx_ring.size;
	      munmap (instance->buffer, ringsize);
	      instance->buffer = MAP_FAILED;
	    }
	  /* Tell the kernel to destroy the rings. */
	  struct tpacket_req req;
	  memset (&req, 0, sizeof (req));
	  setsockopt (instance->fd, SOL_PACKET, PACKET_RX_RING, (void *) &req,
		      sizeof (req));
	  if (instance->tx_ring.size)
	    setsockopt (instance->fd, SOL_PACKET, PACKET_TX_RING,
			(void *) &req, sizeof (req));
	  close (instance->fd);
	}
      if (instance->name)
	{
	  free (instance->name);
	  instance->name = NULL;
	}
      free (instance);
    }
}

static int
iface_get_arptype (AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  struct ifreq ifr;

  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", instance->name);

  if (ioctl (instance->fd, SIOCGIFHWADDR, &ifr) == -1)
    {
      if (errno == ENODEV)
	return DAQ_ERROR_NODEV;
      return DAQ_ERROR;
    }

  return ifr.ifr_hwaddr.sa_family;
}

static AFPacketInstance *
create_instance (AFPacket_Context_t *afpc, const char *device)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance = NULL;
  struct ifreq ifr;
  socklen_t len;
  int val;

  instance = calloc (1, sizeof (AFPacketInstance));
  if (!instance)
    {
      SET_ERROR (afpc->modinst,
		 "%s: Could not allocate a new instance structure.", __func__);
      goto err;
    }
  instance->buffer = MAP_FAILED;

  if ((instance->name = strdup (device)) == NULL)
    {
      SET_ERROR (afpc->modinst,
		 "%s: Could not allocate a copy of the device name.",
		 __func__);
      goto err;
      ;
    }

  /* Open the PF_PACKET raw socket to receive all network traffic completely
     unmodified. We use 0 for the protocol so that the packet pseudo-interface
     will not go into a running
      state until we bind() it to an interface later with a real protocol. */
  instance->fd = socket (PF_PACKET, SOCK_RAW, 0);
  if (instance->fd == -1)
    {
      SET_ERROR (afpc->modinst, "%s: Could not open the PF_PACKET socket: %s",
		 __func__, strerror (errno));
      goto err;
    }

  /* Find the device index of the specified interface. */
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, device, sizeof (ifr.ifr_name));
  if (ioctl (instance->fd, SIOCGIFINDEX, &ifr) == -1)
    {
      SET_ERROR (afpc->modinst, "%s: Could not find index for device %s",
		 __func__, instance->name);
      goto err;
    }
  instance->index = ifr.ifr_ifindex;

  /* Probe whether the kernel supports TPACKET_V2 */
  val = TPACKET_V2;
  len = sizeof (val);
  if (getsockopt (instance->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0)
    {
      SET_ERROR (afpc->modinst,
		 "Couldn't retrieve TPACKET_V2 header length: %s",
		 strerror (errno));
      goto err;
    }
  instance->tp_hdrlen = val;

  /* Tell the kernel to use TPACKET_V2 */
  val = TPACKET_V2;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_VERSION, &val,
		  sizeof (val)) < 0)
    {
      SET_ERROR (afpc->modinst,
		 "Couldn't activate TPACKET_V2 on packet socket: %s",
		 strerror (errno));
      goto err;
    }
  instance->tp_version = TPACKET_V2;

  /* Reserve space for VLAN tag reconstruction */
  val = VLAN_TAG_LEN;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_RESERVE, &val,
		  sizeof (val)) < 0)
    {
      SET_ERROR (afpc->modinst,
		 "Couldn't set up a %d-byte reservation packet socket: %s",
		 val, strerror (errno));
      goto err;
    }

  /* Bypass the kernel's qdisc layer when transmitting */
  val = 1;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_QDISC_BYPASS, &val,
		  sizeof (val)) < 0)
    {
      SET_ERROR (afpc->modinst, "Couldn't configure bypassing qdisc on TX: %s",
		 strerror (errno));
      goto err;
    }

  /* Don't block on malformed frames in the TX ring */
  val = 1;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_LOSS, &val, sizeof (val)) <
      0)
    {
      SET_ERROR (afpc->modinst,
		 "Couldn't configure dropping malformed TX packets: %s",
		 strerror (errno));
      goto err;
    }

  /* Get the interface MTU */
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", instance->name);
  if (ioctl (instance->fd, SIOCGIFMTU, &ifr) == -1)
    {
      SET_ERROR (afpc->modinst, "%s: Could not query MTU for '%s': %s (%d)",
		 __func__, instance->name, strerror (errno), errno);
      goto err;
    }
  instance->mtu = ifr.ifr_mtu;

  /* Get the current reservation.  Hopefully it's what we set it to earlier for
   * VLAN reconstruction. */
  if (getsockopt (instance->fd, SOL_PACKET, PACKET_RESERVE, &val, &len) == -1)
    {
      SET_ERROR (afpc->modinst,
		 "%s: Could not query packet reserved space for '%s': %s (%d)",
		 __func__, instance->name, strerror (errno), errno);
      goto err;
    }
  instance->tp_reserve = val;

  /* Bind the socket to the interface with protocol 0 to associate it with the
     interface while not putting it into the running state yet. */
  if (bind_instance_interface (afpc, instance, 0) != 0)
    goto err;

  /* Verify that the link-layer type is ethernet as that's all we're
   * supporting. */
  int arptype = iface_get_arptype (instance);
  if (arptype < 0)
    {
      SET_ERROR (afpc->modinst,
		 "%s: failed to get interface type for device %s: (%d) %s",
		 __func__, instance->name, errno, strerror (errno));
      goto err;
    }

  /* Normal loopback traffic presents itself as ethernet traffic with zeroed
     out MAC addresses, and injected traffic shows (ala tcpreplay) shows up
     with populated ethernet headers.  Either way, we can just treat it like
     normal ethernet traffic and handle it. */
  if (arptype != ARPHRD_ETHER && arptype != ARPHRD_LOOPBACK)
    {
      SET_ERROR (afpc->modinst, "%s: invalid interface type for device %s: %d",
		 __func__, instance->name, arptype);
      goto err;
    }

  /* Turn on promiscuous mode for the device. */
  struct packet_mreq mr;
  memset (&mr, 0, sizeof (mr));
  mr.mr_ifindex = instance->index;
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		  sizeof (mr)) == -1)
    {
      SET_ERROR (afpc->modinst, "%s: setsockopt: %s", __func__,
		 strerror (errno));
      goto err;
    }

  if (afpc->debug)
    {
      printf ("[%s]\n", instance->name);
      printf ("  TPacket Version: %u\n", instance->tp_version);
      printf ("  TPacket Header Length: %u\n", instance->tp_hdrlen);
      printf ("  MTU: %d\n", instance->mtu);
      printf ("  Reservation: %u\n", instance->tp_reserve);
    }

  return instance;

err:
  destroy_instance (instance);
  return NULL;
}

static void
calculate_frame_size (AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  /* Calculate the TPACKET frame size to use.
      From packet_mmap.txt in the Linux kernel documentation:

	  Frame structure:
	     - Start. Frame must be aligned to TPACKET_ALIGNMENT=16
	     - struct tpacket_hdr
	     - pad to TPACKET_ALIGNMENT=16
	     - struct sockaddr_ll
	     - Gap, chosen so that packet data (Start+tp_net) aligns to
	       TPACKET_ALIGNMENT=16
	     - Start+tp_mac: [ Optional MAC header ]
	     - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
	     - Pad to align to TPACKET_ALIGNMENT=16

      The space we reserve for VLAN reconstruction sits before the MAC header.
      I'm aware the ETH_HLEN should always be less than 16, but I just want
     this logic to as closely match that in the kernel as possible.
  */
  unsigned tp_hdrlen_sll =
    TPACKET_ALIGN (instance->tp_hdrlen) + sizeof (struct sockaddr_ll);
  unsigned netoff =
    TPACKET_ALIGN (tp_hdrlen_sll + (ETH_HLEN < 16 ? 16 : ETH_HLEN)) +
    instance->tp_reserve;
  unsigned macoff = netoff - ETH_HLEN;

  instance->tp_frame_size = TPACKET_ALIGN (macoff + afpc->snaplen);
  instance->actual_snaplen = instance->tp_frame_size - macoff;
}

static int
calculate_layout (AFPacket_Context_t *afpc, AFPacketInstance *instance,
		  struct tpacket_req *layout, int order)
{
  fprintf (stderr, "func: %s\n", __func__);
  unsigned int frames_per_block;

  /* Use the pre-calculated frame size. */
  layout->tp_frame_size = instance->tp_frame_size;

  /* Calculate the minimum block size required. */
  layout->tp_block_size = getpagesize () << order;
  while (layout->tp_block_size < layout->tp_frame_size)
    layout->tp_block_size <<= 1;
  frames_per_block = layout->tp_block_size / layout->tp_frame_size;
  if (frames_per_block == 0)
    {
      SET_ERROR (afpc->modinst, "%s: Invalid frames per block (%u/%u) for %s",
		 __func__, layout->tp_block_size, layout->tp_frame_size,
		 afpc->device);
      return DAQ_ERROR;
    }

  /* Find the total number of frames required to amount to the requested
     per-interface memory. Then find the number of blocks required to hold
     those packet buffer frames. */
  layout->tp_frame_nr = afpc->ring_size / layout->tp_frame_size;
  layout->tp_block_nr = layout->tp_frame_nr / frames_per_block;
  /* afpc->layout.tp_frame_nr is requested to match frames_per_block * n_blocks
   */
  layout->tp_frame_nr = layout->tp_block_nr * frames_per_block;
  if (afpc->debug)
    {
      printf ("AFPacket Layout:\n");
      printf ("  Frame Size: %u\n", layout->tp_frame_size);
      printf ("  Frames:     %u\n", layout->tp_frame_nr);
      printf ("  Block Size: %u (Order %d)\n", layout->tp_block_size, order);
      printf ("  Blocks:     %u\n", layout->tp_block_nr);
      printf ("  Wasted:     %u\n",
	      layout->tp_block_nr *
		(layout->tp_block_size % layout->tp_frame_size));
    }

  return DAQ_SUCCESS;
}

#define DEFAULT_ORDER 5
static int
create_ring (AFPacket_Context_t *afpc, AFPacketInstance *instance,
	     AFPacketRing *ring, int optname)
{
  fprintf (stderr, "func: %s\n", __func__);
  /* Starting with page allocations of order 5, try to allocate an RX ring in
   * the kernel. */
  for (int order = DEFAULT_ORDER; order >= 0; order--)
    {
      if (calculate_layout (afpc, instance, &ring->layout, order))
	return DAQ_ERROR;

      /* Ask the kernel to create the ring. */
      int rc =
	setsockopt (instance->fd, SOL_PACKET, optname, (void *) &ring->layout,
		    sizeof (struct tpacket_req));
      if (rc)
	{
	  if (errno == ENOMEM)
	    {
	      if (afpc->debug)
		printf ("%s: Allocation of kernel packet ring failed with "
			"order %d, retrying...\n",
			instance->name, order);
	      continue;
	    }
	  SET_ERROR (afpc->modinst,
		     "%s: Couldn't create kernel ring on packet socket: %s",
		     __func__, strerror (errno));
	  return DAQ_ERROR;
	}
      /* Store the total ring size for later. */
      ring->size = ring->layout.tp_block_size * ring->layout.tp_block_nr;
      if (afpc->debug)
	printf ("Created a ring of type %d with total size of %u\n", optname,
		ring->size);
      return DAQ_SUCCESS;
    }

  /* If we got here, it means we failed allocation on order 0. */
  SET_ERROR (afpc->modinst,
	     "%s: Couldn't allocate enough memory for the kernel packet ring!",
	     instance->name);
  return DAQ_ERROR;
}

static int
mmap_rings (AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  unsigned int ringsize;

  /* Map the ring into userspace. */
  ringsize = instance->rx_ring.size + instance->tx_ring.size;
  instance->buffer =
    mmap (0, ringsize, PROT_READ | PROT_WRITE, MAP_SHARED, instance->fd, 0);
  if (instance->buffer == MAP_FAILED)
    {
      SET_ERROR (afpc->modinst, "%s: Could not MMAP the ring: %s", __func__,
		 strerror (errno));
      return DAQ_ERROR;
    }
  instance->rx_ring.start = instance->buffer;
  if (instance->tx_ring.size)
    instance->tx_ring.start =
      (uint8_t *) instance->buffer + instance->rx_ring.size;

  return DAQ_SUCCESS;
}

static int
create_instance_rings (AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  /* Calculate the frame size to request from the kernel. */
  calculate_frame_size (afpc, instance);

  /* Request the kernel RX ring from af_packet... */
  if (create_ring (afpc, instance, &instance->rx_ring, PACKET_RX_RING) !=
      DAQ_SUCCESS)
    return DAQ_ERROR;
  /* ...request the kernel TX ring from af_packet if we're in inline mode... */
  if (instance->peer && afpc->use_tx_ring)
    {
      if (create_ring (afpc, instance, &instance->tx_ring, PACKET_TX_RING) !=
	  DAQ_SUCCESS)
	return DAQ_ERROR;
    }
  /* ...map the memory for the kernel ring(s) into userspace... */
  if (mmap_rings (afpc, instance) != DAQ_SUCCESS)
    return DAQ_ERROR;
  /* ...and, finally, set up a userspace ring buffer to represent the kernel RX
   * ring... */
  if (set_up_ring (afpc, instance, &instance->rx_ring) != DAQ_SUCCESS)
    return DAQ_ERROR;
  /* ...as well as one for the TX ring if we're in inline mode... */
  if (instance->peer && afpc->use_tx_ring)
    {
      if (set_up_ring (afpc, instance, &instance->tx_ring) != DAQ_SUCCESS)
	return DAQ_ERROR;
    }

  return DAQ_SUCCESS;
}

static int
configure_fanout (AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  int fanout_arg;

  fanout_arg = ((afpc->fanout_cfg.fanout_type | afpc->fanout_cfg.fanout_flags))
		 << 16 |
	       instance->index;
  if (setsockopt (instance->fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg,
		  sizeof (fanout_arg)) == -1)
    {
      SET_ERROR (afpc->modinst, "%s: Could not configure packet fanout: %s",
		 __func__, strerror (errno));
      return DAQ_ERROR;
    }

  return DAQ_SUCCESS;
}

static int
start_instance (AFPacket_Context_t *afpc, AFPacketInstance *instance)
{
  fprintf (stderr, "func: %s\n", __func__);
  /* Bind the RX ring to this interface. */
  if (bind_instance_interface (afpc, instance, ETH_P_ALL) != 0)
    return -1;

  /* Configure packet fanout if requested.  This must happen after the final
   * binding. */
  if (afpc->fanout_cfg.enabled &&
      configure_fanout (afpc, instance) != DAQ_SUCCESS)
    return -1;

  instance->active = true;

  return 0;
}

static void
update_hw_stats (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;
  struct tpacket_stats kstats;
  socklen_t len = sizeof (struct tpacket_stats);

  for (instance = afpc->instances; instance; instance = instance->next)
    {
      if (!instance->active)
	continue;
      memset (&kstats, 0, len);
      if (getsockopt (instance->fd, SOL_PACKET, PACKET_STATISTICS, &kstats,
		      &len) > -1)
	{
	  /* tp_packets is a superset of tp_drops as it is incremented prior to
	     the processing
	      that determines the copy will be dropped/not made. */
	  afpc->stats.hw_packets_received +=
	    kstats.tp_packets - kstats.tp_drops;
	  afpc->stats.hw_packets_dropped += kstats.tp_drops;
	}
      else
	fprintf (stderr, "Failed to get stats for %s: %d %s\n", instance->name,
		 errno, strerror (errno));
    }
}

static int
af_packet_close (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;

  if (!afpc)
    return -1;

  /* Cache the latest hardware stats before stopping. */
  update_hw_stats (afpc);

  while ((instance = afpc->instances) != NULL)
    {
      afpc->instances = instance->next;
      destroy_instance (instance);
    }

#ifdef LIBPCAP_AVAILABLE
  pcap_freecode (&afpc->fcode);
#endif

  return 0;
}

static int
create_bridge (AFPacket_Context_t *afpc, const char *device_name1,
	       const char *device_name2)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance, *peer1, *peer2;

  peer1 = peer2 = NULL;
  for (instance = afpc->instances; instance; instance = instance->next)
    {
      if (!strcmp (instance->name, device_name1))
	peer1 = instance;
      else if (!strcmp (instance->name, device_name2))
	peer2 = instance;
    }

  if (!peer1 || !peer2)
    return DAQ_ERROR_NODEV;

  peer1->peer = peer2;
  peer2->peer = peer1;

  return DAQ_SUCCESS;
}

static void
reset_stats (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;
  struct tpacket_stats kstats;
  socklen_t len = sizeof (struct tpacket_stats);

  memset (&afpc->stats, 0, sizeof (DAQ_Stats_t));
  /* Just call PACKET_STATISTICS to clear each instance's stats. */
  for (instance = afpc->instances; instance; instance = instance->next)
    getsockopt (instance->fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &len);
}

static int
afpacket_daq_module_load (const DAQ_BaseAPI_t *base_api)
{
  fprintf (stderr, "func: %s\n", __func__);
  if (base_api->api_version != DAQ_BASE_API_VERSION ||
      base_api->api_size != sizeof (DAQ_BaseAPI_t))
    return DAQ_ERROR;

  daq_base_api = *base_api;

  return DAQ_SUCCESS;
}

static int
afpacket_daq_module_unload (void)
{
  fprintf (stderr, "func: %s\n", __func__);
  memset (&daq_base_api, 0, sizeof (daq_base_api));
  return DAQ_SUCCESS;
}

static int
afpacket_daq_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
  fprintf (stderr, "func: %s\n", __func__);
  *var_desc_table = afpacket_variable_descriptions;

  return sizeof (afpacket_variable_descriptions) / sizeof (DAQ_VariableDesc_t);
}

static int
afpacket_daq_instantiate (const DAQ_ModuleConfig_h modcfg,
			  DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc;
  AFPacketInstance *afi;
  const char *size_str = NULL;
  char *name1, *name2, *dev;
  char intf[IFNAMSIZ];
  size_t len;
  int num_intfs = 0;
  int rval = DAQ_ERROR;

  afpc = calloc (1, sizeof (AFPacket_Context_t));
  if (!afpc)
    {
      SET_ERROR (modinst,
		 "%s: Couldn't allocate memory for the new AFPacket context!",
		 __func__);
      rval = DAQ_ERROR_NOMEM;
      goto err;
    }
  afpc->modinst = modinst;

  afpc->device = strdup (daq_base_api.config_get_input (modcfg));
  if (!afpc->device)
    {
      SET_ERROR (modinst,
		 "%s: Couldn't allocate memory for the device string!",
		 __func__);
      rval = DAQ_ERROR_NOMEM;
      goto err;
    }

  afpc->snaplen = daq_base_api.config_get_snaplen (modcfg);
  afpc->timeout = (int) daq_base_api.config_get_timeout (modcfg);
  if (afpc->timeout == 0)
    afpc->timeout = -1;

  dev = afpc->device;
  if (*dev == ':' || ((len = strlen (dev)) > 0 && *(dev + len - 1) == ':') ||
      (daq_base_api.config_get_mode (modcfg) == DAQ_MODE_PASSIVE &&
       strstr (dev, "::")))
    {
      SET_ERROR (modinst, "%s: Invalid interface specification: '%s'!",
		 __func__, afpc->device);
      goto err;
    }

  const char *varKey, *varValue;
  daq_base_api.config_first_variable (modcfg, &varKey, &varValue);
  while (varKey)
    {
      if (!strcmp (varKey, "buffer_size_mb"))
	size_str = varValue;
      else if (!strcmp (varKey, "debug"))
	afpc->debug = true;
      else if (!strcmp (varKey, "fanout_type"))
	{
	  if (!varValue)
	    {
	      SET_ERROR (modinst, "%s: %s requires an argument!", __func__,
			 varKey);
	      goto err;
	    }
	  /* Using anything other than 'hash' is probably asking for trouble,
	     but I'll never stop you from shooting yourself in the foot. */
	  if (!strcmp (varValue, "hash"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_HASH;
	  else if (!strcmp (varValue, "lb"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_LB;
	  else if (!strcmp (varValue, "cpu"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_CPU;
	  else if (!strcmp (varValue, "rollover"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_ROLLOVER;
	  else if (!strcmp (varValue, "rnd"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_RND;
	  else if (!strcmp (varValue, "qm"))
	    afpc->fanout_cfg.fanout_type = PACKET_FANOUT_QM;
	  else
	    {
	      SET_ERROR (modinst, "%s: Unrecognized argument for %s: '%s'!",
			 __func__, varKey, varValue);
	      goto err;
	    }
	  afpc->fanout_cfg.enabled = true;
	}
      else if (!strcmp (varKey, "fanout_flag"))
	{
	  if (!varValue)
	    {
	      SET_ERROR (modinst, "%s: %s requires an argument!", __func__,
			 varKey);
	      goto err;
	    }
	  if (!strcmp (varValue, "rollover"))
	    afpc->fanout_cfg.fanout_flags |= PACKET_FANOUT_FLAG_ROLLOVER;
	  else if (!strcmp (varValue, "defrag"))
	    afpc->fanout_cfg.fanout_flags |= PACKET_FANOUT_FLAG_DEFRAG;
	  else
	    {
	      SET_ERROR (modinst, "%s: Unrecognized argument for %s: '%s'!",
			 __func__, varKey, varValue);
	      goto err;
	    }
	}
      else if (!strcmp (varKey, "use_tx_ring"))
	afpc->use_tx_ring = true;

      daq_base_api.config_next_variable (modcfg, &varKey, &varValue);
    }

  uint32_t size;
  if (size_str && strcmp ("max", size_str) != 0)
    size = strtoul (size_str, NULL, 10);
  else
    size = AF_PACKET_DEFAULT_BUFFER_SIZE;
  /* The size is specified in megabytes.  Convert it to bytes. */
  size = size * 1024 * 1024;

  while (*dev != '\0')
    {
      len = strcspn (dev, ":");
      if (len >= IFNAMSIZ)
	{
	  SET_ERROR (modinst, "%s: Interface name too long! (%zu)", __func__,
		     len);
	  goto err;
	}
      if (len != 0)
	{
	  afpc->intf_count++;
	  if (afpc->intf_count >= AF_PACKET_MAX_INTERFACES)
	    {
	      SET_ERROR (modinst,
			 "%s: Using more than %d interfaces is not supported!",
			 __func__, AF_PACKET_MAX_INTERFACES);
	      goto err;
	    }
	  snprintf (intf, len + 1, "%s", dev);
	  afi = create_instance (afpc, intf);
	  if (!afi)
	    goto err;

	  afi->next = afpc->instances;
	  afpc->instances = afi;
	  num_intfs++;
	  if (daq_base_api.config_get_mode (modcfg) != DAQ_MODE_PASSIVE)
	    {
	      if (num_intfs == 2)
		{
		  name1 = afpc->instances->next->name;
		  name2 = afpc->instances->name;

		  if (create_bridge (afpc, name1, name2) != DAQ_SUCCESS)
		    {
		      SET_ERROR (
			modinst,
			"%s: Couldn't create the bridge between %s and %s!",
			__func__, name1, name2);
		      goto err;
		    }
		  num_intfs = 0;
		}
	      else if (num_intfs > 2)
		break;
	    }
	}
      else
	len = 1;
      dev += len;
    }

  /* If there are any leftover unbridged interfaces and we're not in Passive
   * mode, error out. */
  if (!afpc->instances ||
      (daq_base_api.config_get_mode (modcfg) != DAQ_MODE_PASSIVE &&
       num_intfs != 0))
    {
      SET_ERROR (modinst, "%s: Invalid interface specification: '%s'!",
		 __func__, afpc->device);
      goto err;
    }

  /*
   * Determine the dimensions of the kernel RX/TX ring(s) to request.
   * Divide the total packet buffer memory evenly across the number of rings.
   * (One per passive interface, two per inline.)
   */
  unsigned num_rings = 0;
  for (afi = afpc->instances; afi; afi = afi->next)
    num_rings += (afi->peer && afpc->use_tx_ring) ? 2 : 1;
  afpc->ring_size = size / num_rings;

  /* Create the RX (and potentially TX) rings and map them into userspace. */
  for (afi = afpc->instances; afi; afi = afi->next)
    {
      if ((rval = create_instance_rings (afpc, afi)) != DAQ_SUCCESS)
	goto err;
    }

  /* Finally, create the message buffer pool. */
  uint32_t pool_size = daq_base_api.config_get_msg_pool_size (modcfg);
  if (pool_size == 0)
    {
      /* Default the pool size to 10% of the allocated RX frames. */
      for (afi = afpc->instances; afi; afi = afi->next)
	pool_size += afi->rx_ring.layout.tp_frame_nr;
      pool_size /= 10;
    }
  if ((rval = create_packet_pool (afpc, pool_size)) != DAQ_SUCCESS)
    goto err;

  afpc->curr_instance = afpc->instances;

  *ctxt_ptr = afpc;

  return DAQ_SUCCESS;

err:
  if (afpc)
    {
      af_packet_close (afpc);
      if (afpc->device)
	free (afpc->device);
      destroy_packet_pool (afpc);
      free (afpc);
    }
  return rval;
}

static void
afpacket_daq_destroy (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  af_packet_close (afpc);
  if (afpc->device)
    free (afpc->device);
  if (afpc->filter)
    free (afpc->filter);
  destroy_packet_pool (afpc);
  free (afpc);
}

static int
afpacket_daq_set_filter (void *handle, const char *filter)
{
  fprintf (stderr, "func: %s\n", __func__);
#ifdef LIBPCAP_AVAILABLE
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
  struct bpf_program fcode;

  if (afpc->filter)
    free (afpc->filter);

  afpc->filter = strdup (filter);
  if (!afpc->filter)
    {
      SET_ERROR (afpc->modinst,
		 "%s: Couldn't allocate memory for the filter string!",
		 __func__);
      return DAQ_ERROR;
    }

  pthread_mutex_lock (&bpf_mutex);
  if (pcap_compile_nopcap (afpc->snaplen, DLT_EN10MB, &fcode, afpc->filter, 1,
			   PCAP_NETMASK_UNKNOWN) == -1)
    {
      pthread_mutex_unlock (&bpf_mutex);
      SET_ERROR (afpc->modinst, "%s: BPF state machine compilation failed!",
		 __func__);
      return DAQ_ERROR;
    }
  pthread_mutex_unlock (&bpf_mutex);

  pcap_freecode (&afpc->fcode);
  afpc->fcode.bf_len = fcode.bf_len;
  afpc->fcode.bf_insns = fcode.bf_insns;

  return DAQ_SUCCESS;
#else
  return DAQ_ERROR_NOTSUP;
#endif
}

static int
afpacket_daq_start (void *handle)
{
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;

  for (instance = afpc->instances; instance; instance = instance->next)
    {
      if (start_instance (afpc, instance) != 0)
	return DAQ_ERROR;
    }

  reset_stats (afpc);

  return DAQ_SUCCESS;
}

static inline int
afpacket_transmit_packet (AFPacketInstance *egress, const uint8_t *packet_data,
			  unsigned int len)
{
  fprintf (stderr, "func: %s\n", __func__);
  if (egress)
    {
      if (egress->tx_ring.size)
	{
	  AFPacketEntry *entry;

	  entry = egress->tx_ring.cursor;
	  if (entry->hdr.h2->tp_status != TP_STATUS_AVAILABLE)
	    {
	      /* FIXME: This should probably wait for a TX slot to free up via
	       * poll(). */
	      return DAQ_ERROR_AGAIN;
	    }
	  memcpy (entry->hdr.raw + TPACKET_ALIGN (egress->tp_hdrlen),
		  packet_data, len);
	  entry->hdr.h2->tp_len = len;
	  entry->hdr.h2->tp_status = TP_STATUS_SEND_REQUEST;
	  /* FIXME: This should call sendto() with MSG_DONTWAIT and handle
	     no-buffer conditions gracefully.
	      Performance without MSG_DONTWAIT is apparently pretty miserable.
	   */
	  if (send (egress->fd, NULL, 0, 0) < 0)
	    return DAQ_ERROR;
	  egress->tx_ring.cursor = entry->next;
	}
      else
	{
	  while (send (egress->fd, packet_data, len, 0) < 0)
	    {
	      if (errno == ENOBUFS)
		{
		  struct pollfd pfd;
		  pfd.fd = egress->fd;
		  pfd.revents = 0;
		  pfd.events = POLLOUT;
		  if (poll (&pfd, 1, 10) > 0 && (pfd.revents & POLLOUT))
		    continue;
		}
	      return DAQ_ERROR;
	    }
	}
    }

  return DAQ_SUCCESS;
}

static int
afpacket_inject_packet (AFPacket_Context_t *afpc, AFPacketInstance *egress,
			const uint8_t *data, uint32_t data_len)
{
  fprintf (stderr, "func: %s\n", __func__);
  if (!egress)
    {
      SET_ERROR (
	afpc->modinst,
	"%s: Could not determine which instance to inject the packet out of!",
	__func__);
      return DAQ_ERROR;
    }

  int rval = afpacket_transmit_packet (egress, data, data_len);
  if (rval != DAQ_SUCCESS)
    {
      if (rval == DAQ_ERROR_AGAIN)
	SET_ERROR (afpc->modinst,
		   "%s: Could not send packet because the TX ring is full.",
		   __func__);
      else
	SET_ERROR (afpc->modinst, "%s: Error sending packet: %s (%d)",
		   __func__, strerror (errno), errno);
      return rval;
    }

  afpc->stats.packets_injected++;

  return DAQ_SUCCESS;
}

static int
afpacket_daq_inject (void *handle, DAQ_MsgType type, const void *hdr,
		     const uint8_t *data, uint32_t data_len)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  if (type != DAQ_MSG_TYPE_PACKET)
    return DAQ_ERROR_NOTSUP;

  const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *) hdr;
  AFPacketInstance *egress;

  for (egress = afpc->instances; egress; egress = egress->next)
    {
      if (egress->index == pkthdr->ingress_index)
	break;
    }

  return afpacket_inject_packet (afpc, egress, data, data_len);
}

static int
afpacket_daq_inject_relative (void *handle, const DAQ_Msg_t *msg,
			      const uint8_t *data, uint32_t data_len,
			      int reverse)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
  AFPacketPktDesc *desc = (AFPacketPktDesc *) msg->priv;
  AFPacketInstance *egress = reverse ? desc->instance : desc->instance->peer;

  return afpacket_inject_packet (afpc, egress, data, data_len);
}

static int
afpacket_daq_interrupt (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  afpc->interrupted = true;

  return DAQ_SUCCESS;
}

static int
afpacket_daq_stop (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  af_packet_close (afpc);

  return DAQ_SUCCESS;
}

static int
afpacket_daq_ioctl (void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  /* Only supports GET_DEVICE_INDEX for now */
  if (cmd != DIOCTL_GET_DEVICE_INDEX ||
      arglen != sizeof (DIOCTL_QueryDeviceIndex))
    return DAQ_ERROR_NOTSUP;

  DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *) arg;

  if (!qdi->device)
    {
      SET_ERROR (afpc->modinst, "No device name to find the index of!");
      return DAQ_ERROR_INVAL;
    }

  for (AFPacketInstance *instance = afpc->instances; instance;
       instance = instance->next)
    {
      if (!strcmp (qdi->device, instance->name))
	{
	  qdi->index = instance->index;
	  return DAQ_SUCCESS;
	}
    }

  return DAQ_ERROR_NODEV;
}

static int
afpacket_daq_get_stats (void *handle, DAQ_Stats_t *stats)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  update_hw_stats (afpc);
  memcpy (stats, &afpc->stats, sizeof (DAQ_Stats_t));

  return DAQ_SUCCESS;
}

static void
afpacket_daq_reset_stats (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  reset_stats (afpc);
}

static int
afpacket_daq_get_snaplen (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  /* Note: This returns the maximum capture length that will be returned by the
     kernel. It is slightly larger than the originally requested snaplen due to
     reserving room
      for reconstructing the VLAN tag as well as rounding up due to alignment.
   */

  return afpc->instances->actual_snaplen;
}

static uint32_t
afpacket_daq_get_capabilities (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  uint32_t capabilities = DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
			  DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INTERRUPT |
			  DAQ_CAPA_DEVICE_INDEX;
#ifdef LIBPCAP_AVAILABLE
  capabilities |= DAQ_CAPA_BPF;
#endif
  return capabilities;
}

static int
afpacket_daq_get_datalink_type (void *handle)
{
  fprintf (stderr, "func: %s\n", __func__);
  return DLT_EN10MB;
}

static inline AFPacketEntry *
find_packet (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;
  AFPacketEntry *entry;

  instance = afpc->curr_instance;
  do
    {
      instance = instance->next ? instance->next : afpc->instances;
      if (instance->rx_ring.cursor->hdr.h2->tp_status & TP_STATUS_USER)
	{
	  afpc->curr_instance = instance;
	  entry = instance->rx_ring.cursor;
	  instance->rx_ring.cursor = entry->next;
	  return entry;
	}
    }
  while (instance != afpc->curr_instance);

  return NULL;
}

static inline DAQ_RecvStatus
wait_for_packet (AFPacket_Context_t *afpc)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacketInstance *instance;
  struct pollfd pfd[AF_PACKET_MAX_INTERFACES];
  uint32_t i;

  for (i = 0, instance = afpc->instances; instance;
       i++, instance = instance->next)
    {
      pfd[i].fd = instance->fd;
      pfd[i].revents = 0;
      pfd[i].events = POLLIN;
    }
  /* Chop the timeout into one second chunks (plus any remainer) to improve
     responsiveness to
      interruption when there is no traffic and the timeout is very long (or
     unlimited). */
  int timeout = afpc->timeout;
  while (timeout != 0)
    {
      /* If the receive has been canceled, break out of the loop and return. */
      if (afpc->interrupted)
	{
	  afpc->interrupted = false;
	  return DAQ_RSTAT_INTERRUPTED;
	}

      int poll_timeout;
      if (timeout >= 1000)
	{
	  poll_timeout = 1000;
	  timeout -= 1000;
	}
      else if (timeout > 0)
	{
	  poll_timeout = timeout;
	  timeout = 0;
	}
      else
	poll_timeout = 1000;

      int ret = poll (pfd, afpc->intf_count, poll_timeout);
      /* If some number of of sockets have events returned, check them all for
       * badness. */
      if (ret > 0)
	{
	  for (i = 0; i < afpc->intf_count; i++)
	    {
	      if (pfd[i].revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL))
		{
		  if (pfd[i].revents & (POLLHUP | POLLRDHUP))
		    SET_ERROR (afpc->modinst, "%s: Hang-up on a packet socket",
			       __func__);
		  else if (pfd[i].revents & POLLERR)
		    SET_ERROR (
		      afpc->modinst,
		      "%s: Encountered error condition on a packet socket",
		      __func__);
		  else if (pfd[i].revents & POLLNVAL)
		    SET_ERROR (
		      afpc->modinst,
		      "%s: Invalid polling request on a packet socket",
		      __func__);
		  return DAQ_RSTAT_ERROR;
		}
	    }
	  /* All good! A packet should be waiting for us somewhere. */
	  return DAQ_RSTAT_OK;
	}
      /* If we were interrupted by a signal, start the loop over.  The user
       * should call daq_interrupt to actually exit. */
      if (ret < 0 && errno != EINTR)
	{
	  SET_ERROR (afpc->modinst, "%s: Poll failed: %s (%d)", __func__,
		     strerror (errno), errno);
	  return DAQ_RSTAT_ERROR;
	}
    }

  return DAQ_RSTAT_TIMEOUT;
}

static unsigned
afpacket_daq_msg_receive (void *handle, const unsigned max_recv,
			  const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
  AFPacketInstance *instance;
  DAQ_RecvStatus status = DAQ_RSTAT_OK;
  unsigned idx = 0;

  while (idx < max_recv)
    {
      /* Check to see if the receive has been canceled.  If so, reset it and
       * return appropriately. */
      if (afpc->interrupted)
	{
	  afpc->interrupted = false;
	  status = DAQ_RSTAT_INTERRUPTED;
	  break;
	}

      /* Make sure that we have a packet descriptor available to populate. */
      AFPacketPktDesc *desc = afpc->pool.freelist;
      if (!desc)
	{
	  status = DAQ_RSTAT_NOBUF;
	  break;
	}

      /* Try to find a packet ready for processing from one of the RX rings. */
      AFPacketEntry *entry = find_packet (afpc);
      if (!entry)
	{
	  /* Only block waiting for a packet if we haven't received anything
	   * yet. */
	  /* FIXIT-L - Bad interaction with leading packets filtered by BPF? */
	  if (idx != 0)
	    {
	      status = DAQ_RSTAT_WOULD_BLOCK;
	      break;
	    }
	  status = wait_for_packet (afpc);
	  if (status != DAQ_RSTAT_OK)
	    break;
	  continue;
	}

      unsigned int tp_len, tp_mac, tp_snaplen, tp_sec, tp_usec;
      tp_len = entry->hdr.h2->tp_len;
      tp_mac = entry->hdr.h2->tp_mac;
      tp_snaplen = entry->hdr.h2->tp_snaplen;
      tp_sec = entry->hdr.h2->tp_sec;
      tp_usec = entry->hdr.h2->tp_nsec / 1000;
      instance = afpc->curr_instance;
      if (tp_mac + tp_snaplen > instance->rx_ring.layout.tp_frame_size)
	{
	  SET_ERROR (afpc->modinst,
		     "%s: Corrupted frame on kernel ring (MAC offset %u + "
		     "CapLen %u > FrameSize %d)",
		     __func__, tp_mac, tp_snaplen,
		     afpc->curr_instance->rx_ring.layout.tp_frame_size);
	  status = DAQ_RSTAT_ERROR;
	  break;
	}

      uint8_t *data = entry->hdr.raw + tp_mac;
      /* Make a valiant attempt at reconstructing the VLAN tag if it has been
	 stripped by moving the MAC addresses backward into the reserved space
	 to make room for the VLAN tag and filling that tag structure in.  */
      if ((entry->hdr.h2->tp_vlan_tci ||
	   (entry->hdr.h2->tp_status & TP_STATUS_VLAN_VALID)) &&
	  tp_snaplen >= (unsigned int) vlan_offset)
	{
	  struct vlan_tag *tag;

	  data -= VLAN_TAG_LEN;
	  memmove ((void *) data, data + VLAN_TAG_LEN, vlan_offset);

	  tag = (struct vlan_tag *) (data + vlan_offset);
	  if (entry->hdr.h2->tp_vlan_tpid &&
	      (entry->hdr.h2->tp_status & TP_STATUS_VLAN_TPID_VALID))
	    tag->vlan_tpid = htons (entry->hdr.h2->tp_vlan_tpid);
	  else
	    tag->vlan_tpid = htons (ETH_P_8021Q);
	  tag->vlan_tci = htons (entry->hdr.h2->tp_vlan_tci);

	  tp_snaplen += VLAN_TAG_LEN;
	  tp_len += VLAN_TAG_LEN;
	}
#ifdef LIBPCAP_AVAILABLE
      /* Check to see if this hits the BPF.  If it does, dispose of it and
	 move on to the next packet (transmitting in the inline scenario). */
      if (afpc->fcode.bf_insns &&
	  bpf_filter (afpc->fcode.bf_insns, data, tp_len, tp_snaplen) == 0)
	{
	  afpc->stats.packets_filtered++;
	  afpacket_transmit_packet (instance->peer, data, tp_snaplen);
	  entry->hdr.h2->tp_status = TP_STATUS_KERNEL;
	  continue;
	}
#endif
      afpc->stats.packets_received++;

      /* Populate the packet descriptor, copying the packet data and releasing
	 the packet ring entry back to the kernel for reuse. */
      memcpy (desc->data, data, tp_snaplen);
      entry->hdr.h2->tp_status = TP_STATUS_KERNEL;
      desc->instance = instance;
      desc->length = tp_snaplen;

      /* Next, set up the DAQ message.  Most fields are prepopulated and
       * unchanging. */
      DAQ_Msg_t *msg = &desc->msg;
      msg->data_len = tp_snaplen;

      /* Then, set up the DAQ packet header. */
      DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
      pkthdr->ts.tv_sec = tp_sec;
      pkthdr->ts.tv_usec = tp_usec;
      pkthdr->pktlen = tp_len;
      pkthdr->ingress_index = instance->index;
      pkthdr->egress_index =
	instance->peer ? instance->peer->index : DAQ_PKTHDR_UNKNOWN;
      pkthdr->flags = 0;
      /* The following fields should remain in their virgin state:
	  address_space_id (0)
	  ingress_group (DAQ_PKTHDR_UNKNOWN)
	  egress_group (DAQ_PKTHDR_UNKNOWN)
	  opaque (0)
	  flow_id (0)
       */

      /* Last, but not least, extract this descriptor from the free list and
	 place the message in the return vector. */
      afpc->pool.freelist = desc->next;
      desc->next = NULL;
      afpc->pool.info.available--;
      msgs[idx] = &desc->msg;

      idx++;
    }

  *rstat = status;

  return idx;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
  DAQ_VERDICT_PASS,  /* DAQ_VERDICT_PASS */
  DAQ_VERDICT_BLOCK, /* DAQ_VERDICT_BLOCK */
  DAQ_VERDICT_PASS,  /* DAQ_VERDICT_REPLACE */
  DAQ_VERDICT_PASS,  /* DAQ_VERDICT_WHITELIST */
  DAQ_VERDICT_BLOCK, /* DAQ_VERDICT_BLACKLIST */
  DAQ_VERDICT_PASS,  /* DAQ_VERDICT_IGNORE */
  DAQ_VERDICT_BLOCK  /* DAQ_VERDICT_RETRY */
};

static int
afpacket_daq_msg_finalize (void *handle, const DAQ_Msg_t *msg,
			   DAQ_Verdict verdict)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;
  AFPacketPktDesc *desc = (AFPacketPktDesc *) msg->priv;

  /* Sanitize and enact the verdict. */
  if (verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;
  afpc->stats.verdicts[verdict]++;
  verdict = verdict_translation_table[verdict];
  if (verdict == DAQ_VERDICT_PASS)
    afpacket_transmit_packet (desc->instance->peer, desc->data, desc->length);

  /* Toss the descriptor back on the free list for reuse. */
  desc->next = afpc->pool.freelist;
  afpc->pool.freelist = desc;
  afpc->pool.info.available++;

  return DAQ_SUCCESS;
}

static int
afpacket_daq_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
  fprintf (stderr, "func: %s\n", __func__);
  AFPacket_Context_t *afpc = (AFPacket_Context_t *) handle;

  *info = afpc->pool.info;

  return DAQ_SUCCESS;
}

DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA = {
  /* .api_version = */ DAQ_MODULE_API_VERSION,
  /* .api_size = */ sizeof (DAQ_ModuleAPI_t),
  /* .module_version = */ DAQ_AFPACKET_VERSION,
  /* .name = */ "afpacket",
  /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE |
    DAQ_TYPE_MULTI_INSTANCE,
  /* .load = */ afpacket_daq_module_load,
  /* .unload = */ afpacket_daq_module_unload,
  /* .get_variable_descs = */ afpacket_daq_get_variable_descs,
  /* .instantiate = */ afpacket_daq_instantiate,
  /* .destroy = */ afpacket_daq_destroy,
  /* .set_filter = */ afpacket_daq_set_filter,
  /* .start = */ afpacket_daq_start,
  /* .inject = */ afpacket_daq_inject,
  /* .inject_relative = */ afpacket_daq_inject_relative,
  /* .interrupt = */ afpacket_daq_interrupt,
  /* .stop = */ afpacket_daq_stop,
  /* .ioctl = */ afpacket_daq_ioctl,
  /* .get_stats = */ afpacket_daq_get_stats,
  /* .reset_stats = */ afpacket_daq_reset_stats,
  /* .get_snaplen = */ afpacket_daq_get_snaplen,
  /* .get_capabilities = */ afpacket_daq_get_capabilities,
  /* .get_datalink_type = */ afpacket_daq_get_datalink_type,
  /* .config_load = */ NULL,
  /* .config_swap = */ NULL,
  /* .config_free = */ NULL,
  /* .msg_receive = */ afpacket_daq_msg_receive,
  /* .msg_finalize = */ afpacket_daq_msg_finalize,
  /* .get_msg_pool_info = */ afpacket_daq_get_msg_pool_info,
};
