/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Pieter Meyer
 */

/*
 * Asynchronous transceiver (SFP/QSFP) EEPROM reader.
 *
 * Module EEPROM access is slow on most PMDs: it is I2C, either
 * bit-banged in software (e.g. ixgbe: ~1.5-11 ms per byte, depending on
 * the thread's timer slack) or behind a firmware/admin-queue mailbox
 * (e.g. i40e: ~0.3 s per module).  A full SFF-8472 read (512 bytes) can
 * therefore take seconds.  Doing that on the VPP main thread
 * (and, before this change, under the worker barrier) stops forwarding
 * and control-plane punt/inject for the whole read.
 *
 * Reads are done here on a dedicated DPDK control thread, in small
 * chunks, into a per-port cache.  The main thread only ever copies from
 * the cache under a short mutex, and suspends the calling process (never
 * the main loop) while waiting for a refresh.
 */

#include <sys/prctl.h>
#include <pthread.h>
#include <time.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/sfp.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <sched.h>

#include <rte_thread.h>

/* bytes per PMD call; the hw lock is dropped between chunks so that
 * device start/stop on the main thread waits at most one chunk (milliseconds
 * normally; longer when the PMD retries a NACKed byte before failing
 * the call). Larger chunks keep firmware-mailbox PMDs at fewer commands. */
#define DPDK_EEPROM_CHUNK_SIZE	  8
#define DPDK_EEPROM_MAX_LEN	  1024
#define DPDK_EEPROM_CACHE_MAX_AGE 2.0 /* seconds */
/* failed read (empty cage, no I2C, broken module): do not re-read on
 * every show command; a port start/stop still forces a re-read */
#define DPDK_EEPROM_FAIL_MAX_AGE   30.0	 /* seconds */
#define DPDK_EEPROM_READ_TIMEOUT   15.0	 /* seconds, once our read started */
#define DPDK_EEPROM_QUEUE_TIMEOUT  120.0 /* seconds, total incl. queueing */
#define DPDK_EEPROM_WAIT_INTERVAL  10e-3
#define DPDK_EEPROM_TIMER_SLACK_NS 1000UL

/* SFF-8472 A0h byte 92 (diagnostic monitoring type), bit 6: DDM
 * implemented.  Many DACs claim SFF-8472 but have no A2h page. */
#define SFF8472_DIAG_MON_TYPE_OFFSET 92
#define SFF8472_DIAG_MON_DDM	     (1 << 6)

enum
{
  DPDK_EEPROM_IDLE = 0,
  DPDK_EEPROM_QUEUED = 1,
  DPDK_EEPROM_READING = 2,
};

typedef struct
{
  /* serialises PMD access to the module/PHY between the reader thread
   * and dpdk_device_start/stop on the main thread */
  pthread_mutex_t hw_lock;
  /* main thread waiting for hw_lock: reader backs off between chunks
   * (pthread mutexes are not fair) */
  u32 hw_waiters;

  /* protects everything below */
  pthread_mutex_t lock;
  u8 state;	  /* DPDK_EEPROM_IDLE/QUEUED/READING */
  u8 valid;	  /* data[] holds a good image */
  u8 stale;	  /* port restarted since last read: refresh before use */
  int last_rv;	  /* result of the last completed read */
  u32 generation; /* completed reads; 0 = never read */
  f64 last_update;
  u32 type;
  u32 len;
  u8 data[DPDK_EEPROM_MAX_LEN];
} dpdk_eeprom_port_t;

typedef struct
{
  u8 state, valid, stale;
  int last_rv;
  u32 generation;
  f64 age;
} dpdk_eeprom_snapshot_t;

typedef struct
{
  pthread_mutex_t q_lock;
  pthread_cond_t q_cond;
  u32 n_pending;
  u32 next_scan; /* round-robin start, reader thread only */
  u8 thread_running;
  rte_thread_t thread;
  /* written only by the main thread (atomic release), never freed */
  dpdk_eeprom_port_t *ports[RTE_MAX_ETHPORTS];
} dpdk_eeprom_main_t;

static dpdk_eeprom_main_t dpdk_eeprom_main = {
  .q_lock = PTHREAD_MUTEX_INITIALIZER,
  .q_cond = PTHREAD_COND_INITIALIZER,
};

static f64
dpdk_eeprom_now (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (f64) ts.tv_sec + (f64) ts.tv_nsec * 1e-9;
}

static_always_inline dpdk_eeprom_port_t *
dpdk_eeprom_port_load (u32 port_id)
{
  return __atomic_load_n (&dpdk_eeprom_main.ports[port_id], __ATOMIC_ACQUIRE);
}

static void
dpdk_eeprom_hw_lock_reader (dpdk_eeprom_port_t *ep)
{
  /* let a waiting main thread in first */
  while (__atomic_load_n (&ep->hw_waiters, __ATOMIC_ACQUIRE))
    sched_yield ();
  pthread_mutex_lock (&ep->hw_lock);
}

static void
dpdk_eeprom_read_port (dpdk_portid_t port_id, dpdk_eeprom_port_t *ep)
{
  struct rte_eth_dev_module_info mi = { 0 };
  struct rte_dev_eeprom_info ei = { 0 };
  /* thread-local buffer, never touched by the main thread */
  static __thread u8 buf[DPDK_EEPROM_MAX_LEN];
  int rv;
  u32 off;

  dpdk_eeprom_hw_lock_reader (ep);
  rv = rte_eth_dev_get_module_info (port_id, &mi);
  pthread_mutex_unlock (&ep->hw_lock);

  if (rv == 0 && (mi.eeprom_len == 0 || mi.eeprom_len > DPDK_EEPROM_MAX_LEN))
    rv = -EINVAL;

  for (off = 0; rv == 0 && off < mi.eeprom_len; off += DPDK_EEPROM_CHUNK_SIZE)
    {
      /*
       * SFF-8472 without DDM (typical for passive DAC): A2h is absent or
       * meaningless and each NACKed byte can cost
       * PMD-level I2C retries.
       * Serve the A0h page as SFF-8079 instead ("diag" then reports
       * not available, module info still works).
       */
      if (off == RTE_ETH_MODULE_SFF_8079_LEN && mi.type == RTE_ETH_MODULE_SFF_8472 &&
	  !(buf[SFF8472_DIAG_MON_TYPE_OFFSET] & SFF8472_DIAG_MON_DDM))
	{
	  mi.type = RTE_ETH_MODULE_SFF_8079;
	  mi.eeprom_len = RTE_ETH_MODULE_SFF_8079_LEN;
	  break;
	}
      ei.offset = off;
      ei.length = clib_min (DPDK_EEPROM_CHUNK_SIZE, mi.eeprom_len - off);
      ei.data = buf + off;
      dpdk_eeprom_hw_lock_reader (ep);
      rv = rte_eth_dev_get_module_eeprom (port_id, &ei);
      pthread_mutex_unlock (&ep->hw_lock);
      /* A2h unreadable although DDM is advertised: keep A0h */
      if (rv && mi.type == RTE_ETH_MODULE_SFF_8472 && off >= RTE_ETH_MODULE_SFF_8079_LEN)
	{
	  mi.type = RTE_ETH_MODULE_SFF_8079;
	  mi.eeprom_len = RTE_ETH_MODULE_SFF_8079_LEN;
	  rv = 0;
	  break;
	}
    }

  pthread_mutex_lock (&ep->lock);
  ep->last_rv = rv;
  if (rv == 0)
    {
      clib_memcpy_fast (ep->data, buf, mi.eeprom_len);
      ep->len = mi.eeprom_len;
      ep->type = mi.type;
      ep->valid = 1;
    }
  else
    ep->valid = 0; /* no module, unsupported or unreadable */
  ep->last_update = dpdk_eeprom_now ();
  ep->generation++;
  ep->state = DPDK_EEPROM_IDLE;
  pthread_mutex_unlock (&ep->lock);
}

static u32
dpdk_eeprom_thread_fn (void *arg)
{
  dpdk_eeprom_main_t *em = &dpdk_eeprom_main;

  /* PMDs that bit-bang I2C sleep per bit, so nanosleep() granularity
   * dominates their EEPROM cost; the default 50us slack makes a 512-byte
   * ixgbe read ~6 s instead of ~0.7 s */
  prctl (PR_SET_TIMERSLACK, DPDK_EEPROM_TIMER_SLACK_NS);

  while (1)
    {
      dpdk_eeprom_port_t *ep = 0;
      u32 i, port_id = 0;

      pthread_mutex_lock (&em->q_lock);
      while (em->n_pending == 0)
	pthread_cond_wait (&em->q_cond, &em->q_lock);

      /* round-robin so low port ids cannot starve high ones */
      for (i = 0; i < RTE_MAX_ETHPORTS; i++)
	{
	  port_id = (em->next_scan + i) % RTE_MAX_ETHPORTS;
	  ep = dpdk_eeprom_port_load (port_id);
	  if (!ep)
	    continue;
	  pthread_mutex_lock (&ep->lock);
	  if (ep->state == DPDK_EEPROM_QUEUED)
	    {
	      ep->state = DPDK_EEPROM_READING;
	      /* a start/stop from here on marks this read stale again */
	      ep->stale = 0;
	      pthread_mutex_unlock (&ep->lock);
	      break;
	    }
	  pthread_mutex_unlock (&ep->lock);
	}
      if (i == RTE_MAX_ETHPORTS)
	{
	  em->n_pending = 0; /* should not happen */
	  pthread_mutex_unlock (&em->q_lock);
	  continue;
	}
      em->n_pending--;
      em->next_scan = (port_id + 1) % RTE_MAX_ETHPORTS;
      pthread_mutex_unlock (&em->q_lock);

      dpdk_eeprom_read_port (port_id, ep);
    }
  return 0;
}

/* main thread only */
static dpdk_eeprom_port_t *
dpdk_eeprom_get_port (dpdk_portid_t port_id, int create)
{
  dpdk_eeprom_port_t *ep;

  if (port_id >= RTE_MAX_ETHPORTS)
    return 0;

  ep = dpdk_eeprom_port_load (port_id);
  if (ep || !create)
    return ep;

  ep = clib_mem_alloc_aligned (sizeof (*ep), CLIB_CACHE_LINE_BYTES);
  clib_memset (ep, 0, sizeof (*ep));
  pthread_mutex_init (&ep->hw_lock, 0);
  pthread_mutex_init (&ep->lock, 0);

  __atomic_store_n (&dpdk_eeprom_main.ports[port_id], ep, __ATOMIC_RELEASE);
  return ep;
}

/* main thread only */
static int
dpdk_eeprom_request (dpdk_portid_t port_id, dpdk_eeprom_port_t *ep)
{
  dpdk_eeprom_main_t *em = &dpdk_eeprom_main;
  int rv;

  if (!em->thread_running)
    {
      rv = rte_thread_create_control (&em->thread, "vpp-eeprom", dpdk_eeprom_thread_fn, 0);
      if (rv)
	return rv;
      em->thread_running = 1;
    }

  /* lock order: q_lock, then ep->lock (same as the reader) */
  pthread_mutex_lock (&em->q_lock);
  pthread_mutex_lock (&ep->lock);
  if (ep->state == DPDK_EEPROM_IDLE)
    {
      ep->state = DPDK_EEPROM_QUEUED;
      em->n_pending++;
      pthread_cond_signal (&em->q_cond);
    }
  pthread_mutex_unlock (&ep->lock);
  pthread_mutex_unlock (&em->q_lock);
  return 0;
}

/* Snapshot the cache; copies the image into e (if given and valid). */
static void
dpdk_eeprom_snapshot (dpdk_eeprom_port_t *ep, vnet_interface_eeprom_t *e,
		      dpdk_eeprom_snapshot_t *st)
{
  pthread_mutex_lock (&ep->lock);
  st->state = ep->state;
  st->valid = ep->valid;
  st->stale = ep->stale;
  st->last_rv = ep->last_rv;
  st->generation = ep->generation;
  st->age = dpdk_eeprom_now () - ep->last_update;
  if (ep->valid && e)
    {
      clib_memcpy_fast (e->eeprom_raw, ep->data, ep->len);
      e->eeprom_len = ep->len;
      e->eeprom_type = ep->type;
    }
  pthread_mutex_unlock (&ep->lock);
}

static_always_inline int
dpdk_eeprom_is_fresh (dpdk_eeprom_snapshot_t *st)
{
  f64 max_age = st->valid ? DPDK_EEPROM_CACHE_MAX_AGE : DPDK_EEPROM_FAIL_MAX_AGE;

  return st->generation && !st->stale && st->age < max_age;
}

/* Can the caller suspend without stopping the workers? */
static int
dpdk_eeprom_can_wait (vlib_main_t *vm)
{
  if (!vlib_in_process_context (vm))
    return 0;
  if (vlib_get_n_threads () > 1 && vlib_worker_thread_barrier_held ())
    return 0;
  return 1;
}

clib_error_t *
dpdk_eeprom_read (dpdk_device_t *xd, vnet_hw_interface_t *hi, vnet_interface_eeprom_t **eeprom)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_eeprom_port_t *ep;
  vnet_interface_eeprom_t *e;
  dpdk_eeprom_snapshot_t st;
  clib_error_t *err = 0;
  dpdk_portid_t port_id = xd->port_id;
  /* hi and xd may be reallocated while this process is suspended */
  u8 *name = vec_dup (hi->name);
  u32 req_gen;
  f64 t_req, t_read = 0;
  int rv;

  ASSERT (vlib_get_thread_index () == 0);
  *eeprom = 0;

  ep = dpdk_eeprom_get_port (port_id, 1);
  if (!ep)
    {
      err = clib_error_return (0, "invalid port id %u", port_id);
      goto out;
    }

  e = clib_mem_alloc (sizeof (*e));
  clib_memset (e, 0, sizeof (*e));

  dpdk_eeprom_snapshot (ep, e, &st);
  if (dpdk_eeprom_is_fresh (&st))
    goto done; /* fresh result, good or bad */

  req_gen = st.generation;
  rv = dpdk_eeprom_request (port_id, ep);
  if (rv)
    {
      err = clib_error_return (0, "cannot start EEPROM reader thread: %d", rv);
      goto fail;
    }

  if (!dpdk_eeprom_can_wait (vm))
    {
      /* e.g. cli_inband (barrier held): never block, serve what we have */
      if (st.generation)
	goto done;
      err = clib_error_return (0,
			       "EEPROM for %v is being read in the "
			       "background, retry in a few seconds",
			       name);
      goto fail;
    }

  t_req = vlib_time_now (vm);
  while (1)
    {
      vlib_process_suspend (vm, DPDK_EEPROM_WAIT_INTERVAL);
      dpdk_eeprom_snapshot (ep, 0, &st);
      if (st.generation != req_gen)
	break;
      /* time our own read, not the queue in front of it */
      if (st.state == DPDK_EEPROM_READING && t_read == 0)
	t_read = vlib_time_now (vm);
      if ((t_read && vlib_time_now (vm) - t_read > DPDK_EEPROM_READ_TIMEOUT) ||
	  vlib_time_now (vm) - t_req > DPDK_EEPROM_QUEUE_TIMEOUT)
	{
	  err = clib_error_return (0, "EEPROM read timeout for %v", name);
	  goto fail;
	}
    }

  dpdk_eeprom_snapshot (ep, e, &st);

done:
  if (!st.valid)
    {
      err = clib_error_return (0, "EEPROM read error for interface %v (%d)", name, st.last_rv);
      goto fail;
    }
  *eeprom = e;
  goto out;

fail:
  clib_mem_free (e);
out:
  vec_free (name);
  return err;
}

/* Non-blocking: format from cache and kick a background refresh. */
u8 *
format_dpdk_device_module_info (u8 *s, va_list *args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  dpdk_eeprom_port_t *ep;
  vnet_interface_eeprom_t *e;
  dpdk_eeprom_snapshot_t st;
  u32 off;

  if (vlib_get_thread_index () != 0)
    return format (s, "unknown");

  ep = dpdk_eeprom_get_port (xd->port_id, 1);
  if (!ep)
    return format (s, "unknown");

  e = clib_mem_alloc (sizeof (*e));
  clib_memset (e, 0, sizeof (*e));
  dpdk_eeprom_snapshot (ep, e, &st);

  if (!dpdk_eeprom_is_fresh (&st))
    dpdk_eeprom_request (xd->port_id, ep);

  off = e->eeprom_type == RTE_ETH_MODULE_SFF_8436 ? 0x80 : 0;
  if (st.valid && e->eeprom_len >= off + sizeof (sfp_eeprom_t))
    {
      s = format (s, "%U", format_sfp_eeprom, e->eeprom_raw + off);
      if (!dpdk_eeprom_is_fresh (&st))
	s = format (s, " (cached %.0fs ago, refresh queued)", st.age);
    }
  else if (st.generation)
    s = format (s, "unknown"); /* no module / unsupported / read error */
  else
    s = format (s, "not cached yet (background read queued)");

  clib_mem_free (e);
  return s;
}

/* Called around PMD start/stop on the main thread. */
void
dpdk_eeprom_hw_lock (dpdk_device_t *xd)
{
  dpdk_eeprom_port_t *ep = dpdk_eeprom_get_port (xd->port_id, 0);
  if (!ep)
    return;
  __atomic_add_fetch (&ep->hw_waiters, 1, __ATOMIC_RELEASE);
  pthread_mutex_lock (&ep->hw_lock);
  __atomic_sub_fetch (&ep->hw_waiters, 1, __ATOMIC_RELEASE);
}

void
dpdk_eeprom_hw_unlock (dpdk_device_t *xd)
{
  dpdk_eeprom_port_t *ep = dpdk_eeprom_get_port (xd->port_id, 0);
  if (!ep)
    return;
  pthread_mutex_unlock (&ep->hw_lock);
  /* module may have been swapped while the port was down: re-read
   * before the cached image is used again */
  pthread_mutex_lock (&ep->lock);
  ep->stale = 1;
  pthread_mutex_unlock (&ep->lock);
}
