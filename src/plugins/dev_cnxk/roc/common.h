/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_roc_common_h
#define included_onp_drv_roc_common_h

typedef uint64_t unaligned_uint64_t __attribute__ ((aligned (1)));
typedef uint32_t unaligned_uint32_t __attribute__ ((aligned (1)));
typedef uint16_t unaligned_uint16_t __attribute__ ((aligned (1)));

#define __plt_always_inline inline __attribute__ ((__always_inline__))

#if defined(__ARM_FEATURE_SVE2)
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse+sve2\n"
#elif defined(__ARM_FEATURE_SVE)
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse+sve\n"
#else
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse\n"
#endif

/* C extension macro for environments lacking C11 features. */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#define PLT_STD_C11 __extension__
#else
#define PLT_STD_C11
#endif

#ifndef BITMASK_ULL
#define BITMASK_ULL(h, l)                                                     \
  (((~0ULL) - (1ULL << (l)) + 1) &                                            \
   (~0ULL >> ((__SIZEOF_LONG_LONG__ * 8) - 1 - (h))))
#endif

#define PLT_ALIGN_FLOOR(val, align)                                           \
  (typeof (val)) ((val) & (~((typeof (val)) ((align) -1))))

#define PLT_PTR_ALIGN_FLOOR(ptr, align)                                       \
  ((typeof (ptr)) PLT_ALIGN_FLOOR ((uintptr_t) ptr, align))

#define PLT_PTR_ADD(ptr, x) ((void *) ((uintptr_t) (ptr) + (x)))
#define PLT_PTR_ALIGN_CEIL(ptr, align)                                        \
  PLT_PTR_ALIGN_FLOOR ((typeof (ptr)) PLT_PTR_ADD (ptr, (align) -1), align)

#define PLT_ALIGN_CEIL(val, align)                                            \
  PLT_ALIGN_FLOOR (((val) + ((typeof (val)) (align) -1)), align)

#define PLT_PTR_ALIGN(ptr, align) PLT_PTR_ALIGN_CEIL (ptr, align)

#define PLT_PTR_DIFF(__ptr1, __ptr2)                                          \
  ((uintptr_t) (__ptr1) - (uintptr_t) (__ptr2))

#define PLT_ALIGN(val, align) PLT_ALIGN_CEIL (val, align)

#define PLT_ALIGN_MUL_CEIL(v, mul)                                            \
  ((((v) + (typeof (v)) (mul) -1) / ((typeof (v)) (mul))) * (typeof (v)) (mul))

#ifndef container_of
#define container_of(__ptr, __type, __member)                                 \
  ({                                                                          \
    __typeof__ (((__type *) 0)->__member) *__mptr = (__ptr);                  \
    (__type *) ((uintptr_t) __mptr - offsetof (__type, __member));            \
  })
#endif
#define PLT_DIV_CEIL(x, y)                                                    \
  ({                                                                          \
    __typeof (x) __x = x;                                                     \
    __typeof (y) __y = y;                                                     \
    (__x + __y - 1) / __y;                                                    \
  })

#define __plt_internal
#define __roc_api

#define unlikely PREDICT_FALSE
#define likely	 PREDICT_TRUE

#define PLT_ASSERT	     ASSERT
#define PLT_MEMZONE_NAME     32
#define PLT_MIN		     clib_min
#define PLT_MAX		     clib_max
#define PLT_DIM		     ARRAY_LEN
#define PLT_SET_USED(x)	     (void) (x)
#define PLT_STATIC_ASSERT(s) STATIC_ASSERT (s, "Static assertion failed")
#define PLT_MODEL_MZ_NAME    "roc_model_mz"
#define PLT_CACHE_LINE_SIZE  CLIB_CACHE_LINE_BYTES
#define plt_log2_u32	     max_log2
#define __plt_cache_aligned  __attribute__ ((aligned (PLT_CACHE_LINE_SIZE)))
#define __plt_packed	     __clib_packed

#ifndef __plt_aligned
#define __plt_aligned(x) __clib_aligned (x)
#endif

/* This macro permits both remove and free var within the loop safely. */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                            \
  for ((var) = TAILQ_FIRST ((head));                                          \
       (var) && ((tvar) = TAILQ_NEXT ((var), field), 1); (var) = (tvar))
#endif

#define PLT_TAILQ_FOREACH_SAFE TAILQ_FOREACH_SAFE

#define PLT_ETHER_ADDR_LEN 6 /**< Length of Ethernet address. */

#define plt_cpu_to_be_16 clib_host_to_net_u16
#define plt_be_to_cpu_16 clib_net_to_host_u16
#define plt_cpu_to_be_32 clib_host_to_net_u32
#define plt_be_to_cpu_32 clib_net_to_host_u32
#define plt_cpu_to_be_64 clib_host_to_net_u64
#define plt_be_to_cpu_64 clib_net_to_host_u64
#define plt_iova_t	 cnxk_plt_iova_t

#define PLT_MAX_ETHPORTS  32
#define PLT_PTR_CAST(val) ((void *) (val))
#define PLT_U64_CAST(val) ((uint64_t) (val))
#define PLT_U32_CAST(val) ((uint32_t) (val))
#define PLT_U16_CAST(val) ((uint16_t) (val))

#define plt_mmap       mmap
#define PLT_PROT_READ  PROT_READ
#define PLT_PROT_WRITE PROT_WRITE
#define PLT_MAP_SHARED MAP_SHARED

#define plt_dump	       clib_warning
#define plt_lcore_id()	       __os_thread_index
#define plt_tsc_hz	       cnxk_plt_get_tsc_hz
#define plt_tsc_cycles()       clib_cpu_time_now ()
#define plt_delay_ms	       cnxk_plt_delay_ms
#define plt_delay_us	       cnxk_plt_delay_us
#define plt_spinlock_t	       clib_spinlock_t
#define plt_spinlock_init      clib_spinlock_init
#define plt_spinlock_lock      clib_spinlock_lock
#define plt_spinlock_unlock    clib_spinlock_unlock
#define plt_spinlock_trylock   clib_spinlock_trylock
#define plt_align32prevpow2(x) (1 << min_log2 (x))
#define plt_align32pow2(x)     (1 << max_log2 (x))
#define plt_read32(addr)       cnxk_plt_read32_relaxed ((volatile void *) (addr))
#define plt_write32(val, addr)                                                \
  cnxk_plt_write32_relaxed ((val), (volatile void *) (addr))
#define plt_read64(addr) cnxk_plt_read64_relaxed ((volatile void *) (addr))
#define plt_write64(val, addr)                                                \
  cnxk_plt_write64_relaxed ((val), (volatile void *) (addr))
#define plt_mb	    cnxk_mb
#define plt_wmb	    cnxk_wmb
#define plt_rmb	    cnxk_rmb
#define plt_smp_mb  cnxk_smp_mb
#define plt_smp_wmb cnxk_smp_wmb
#define plt_smp_rmb cnxk_smp_rmb
#define plt_io_mb   cnxk_mb
#define plt_io_wmb  cnxk_wmb
#define plt_io_rmb  cnxk_rmb

#define MAX_VFIO_PCI_BAR_REGIONS     6 /* GENERIC MAPPABLE BAR REGIONS ONLY */
#define PLT_MAX_RXTX_INTR_VEC_ID     1024
#define PLT_INTR_VEC_RXTX_OFFSET     1
#define plt_pci_device		     cnxk_plt_pci_device
#define plt_pci_read_config	     cnxk_plt_pci_read_config
#define plt_pci_find_ext_capability  cnxk_plt_pci_config_find_capability

#define plt_intr_callback_register   cnxk_plt_intr_callback_register
#define plt_intr_callback_unregister cnxk_plt_intr_callback_unregister
#define plt_intr_disable	     cnxk_plt_intr_disable
#define plt_intr_vec_list_index_get  cnxk_plt_intr_vec_list_index_get
#define plt_intr_vec_list_index_set  cnxk_plt_intr_vec_list_index_set
#define plt_intr_vec_list_alloc	     cnxk_plt_intr_vec_list_alloc
#define plt_intr_vec_list_free	     cnxk_plt_intr_vec_list_free

#define plt_thread_is_intr	     cnxk_plt_thread_is_intr
#define plt_intr_callback_fn	     cnxk_plt_pci_intr_callback_fn
#define plt_intr_handle		     cnxk_plt_pci_intr_handle
#define plt_alarm_set		     cnxk_pltarm_set
#define plt_alarm_cancel	     cnxk_pltarm_cancel
#define plt_strlcpy		     cnxk_plt_strlcpy
#define plt_zmalloc(sz, align)	     cnxk_plt_zmalloc (sz, align)
#define plt_free		     cnxk_plt_free
#define plt_realloc		     cnxk_plt_realloc

#define plt_sysfs_value_parse cnxk_plt_sysfs_value_parse
/* We dont have a fencing func which takes args, use gcc inbuilt */
#define plt_atomic_thread_fence __atomic_thread_fence

#define cnxk_plt_err(fmt, args...)                                            \
  vlib_log (VLIB_LOG_LEVEL_ERR, cnxk_logtype_base, "%s():%u " fmt "\n",       \
	    __func__, __LINE__, ##args)

#define cnxk_plt_info(fmt, args...)                                           \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_logtype_base, fmt "\n", ##args)

#define cnxk_plt_warn(fmt, args...)                                           \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cnxk_logtype_base, fmt "\n", ##args)

#define cnxk_plt_print(fmt, args...)                                          \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_logtype_base, fmt "\n", ##args)

#define cnxk_plt_print_no_nl(fmt, args...)                                    \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_logtype_base, fmt, ##args)

#define cnxk_plt_dbg(subsystem, fmt, args...)                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cnxk_logtype_##subsystem,                   \
	    "[%s] %s():%u " fmt "\n", #subsystem, __func__, __LINE__, ##args)

#define plt_err(fmt, ...)   cnxk_plt_err (fmt, ##__VA_ARGS__)
#define plt_info(fmt, ...)  cnxk_plt_info (fmt, ##__VA_ARGS__)
#define plt_warn(fmt, ...)  cnxk_plt_warn (fmt, ##__VA_ARGS__)
#define plt_print(fmt, ...) cnxk_plt_print (fmt, ##__VA_ARGS__)
#define plt_print_no_nl(fmt, ...) cnxk_plt_print_no_nl (fmt, ##__VA_ARGS__)
#define plt_dump_no_nl		  plt_print_no_nl

#define plt_base_dbg(fmt, ...)	cnxk_plt_dbg (base, fmt, ##__VA_ARGS__)
#define plt_cpt_dbg(fmt, ...)	cnxk_plt_dbg (cpt, fmt, ##__VA_ARGS__)
#define plt_mbox_dbg(fmt, ...)	cnxk_plt_dbg (mbox, fmt, ##__VA_ARGS__)
#define plt_npa_dbg(fmt, ...)	cnxk_plt_dbg (npa, fmt, ##__VA_ARGS__)
#define plt_nix_dbg(fmt, ...)	cnxk_plt_dbg (nix, fmt, ##__VA_ARGS__)
#define plt_sso_dbg(fmt, ...)	cnxk_plt_dbg (sso, fmt, ##__VA_ARGS__)
#define plt_npc_dbg(fmt, ...)	cnxk_plt_dbg (npc, fmt, ##__VA_ARGS__)
#define plt_tm_dbg(fmt, ...)	cnxk_plt_dbg (tm, fmt, ##__VA_ARGS__)
#define plt_tim_dbg(fmt, ...)	cnxk_plt_dbg (tim, fmt, ##__VA_ARGS__)
#define plt_pci_dbg(fmt, ...)	cnxk_plt_dbg (pci, fmt, ##__VA_ARGS__)
#define plt_sdp_dbg(fmt, ...)	cnxk_plt_dbg (ep, fmt, ##__VA_ARGS__)
#define plt_bphy_dbg(fmt, ...)	cnxk_plt_dbg (bphy, fmt, ##__VA_ARGS__)
#define plt_iomem_dbg(fmt, ...) cnxk_plt_dbg (iomem, fmt, ##__VA_ARGS__)
#define plt_ml_dbg(fmt, ...)	cnxk_plt_dbg (ml, fmt, ##__VA_ARGS__)

#define ISB() __asm__ volatile("isb" : : : "memory")

#define MRS_WITH_MEM_BARRIER(reg)                                                   \
	({                                                                     \
		uint64_t val;                                                  \
		__asm__ volatile("mrs %0, " #reg : "=r"(val) :: "memory");     \
		val;                                                           \
	})

#define MRS(reg)                                                               \
	({                                                                     \
		uint64_t val;                                                  \
		__asm__ volatile("mrs %0, " #reg : "=r"(val));		       \
		val;                                                           \
	})

typedef struct
{
  u32 seq_num;
} cnxk_seqcount_t;

#define plt_seqcount_t	  cnxk_seqcount_t
#define plt_seqcount_init cnxk_seqcount_init
static_always_inline void
cnxk_seqcount_init (plt_seqcount_t *seqcount)
{
  seqcount->seq_num = 0;
}

/* Init callbacks */
typedef int (*roc_plt_init_cb_t) (void);
int __roc_api roc_plt_init_cb_register (roc_plt_init_cb_t cb);

typedef void (*cnxk_plt_pci_intr_callback_fn) (void *cb_arg);
typedef void (*cnxk_plt_pci_alarm_callback) (void *arg);
typedef u64 cnxk_plt_iova_t;
__plt_internal int cnxk_plt_init (void);

extern vlib_log_class_t cnxk_logtype_base;
extern vlib_log_class_t cnxk_logtype_cpt;
extern vlib_log_class_t cnxk_logtype_mbox;
extern vlib_log_class_t cnxk_logtype_npa;
extern vlib_log_class_t cnxk_logtype_nix;
extern vlib_log_class_t cnxk_logtype_sso;
extern vlib_log_class_t cnxk_logtype_npc;
extern vlib_log_class_t cnxk_logtype_tm;
extern vlib_log_class_t cnxk_logtype_tim;
extern vlib_log_class_t cnxk_logtype_pci;
extern vlib_log_class_t cnxk_logtype_ep;
extern vlib_log_class_t cnxk_logtype_bphy;
extern vlib_log_class_t cnxk_logtype_iomem;
extern vlib_log_class_t cnxk_logtype_ml;

enum cnxk_plt_pci_intr_handle_type
{
  PLT_INTR_HANDLE_UNKNOWN = 0,
  PLT_INTR_HANDLE_VFIO_MSIX,
  PLT_INTR_HANDLE_MAX
};

struct cnxk_plt_pci_intr_handle
{
  int vfio_dev_fd;
  int fd;
  enum cnxk_plt_pci_intr_handle_type type;
  u32 max_intr;
  u32 nb_intr;
  u32 nb_efd;
  u8 efd_counter_size;
  int efds[1024];
  int *intr_vec;
};

struct cnxk_plt_pci_id
{
  u32 class_id;
  u16 vendor_id;
  u16 device_id;
  u16 subsystem_vendor_id;
  u16 subsystem_device_id;
};

typedef struct pci_mem_rsrc
{
  u64 phys_addr;
  u64 len;
  void *addr;
} cnxk_plt_pci_mem_rsrc_t;

typedef struct cnxk_plt_pci_device
{
  cnxk_plt_pci_mem_rsrc_t mem_resource[MAX_VFIO_PCI_BAR_REGIONS];
  struct cnxk_plt_pci_id id;
  struct cnxk_plt_pci_intr_handle *intr_handle;
  u16 max_vfs;
  u8 name[32];
  vnet_dev_t *vnet_dev;
} cnxk_plt_pci_device_t;

static_always_inline u64
cnxk_plt_get_tsc_hz ()
{
  return os_cpu_clock_frequency ();
}

static_always_inline int
cnxk_plt_intr_vec_list_alloc (struct cnxk_plt_pci_intr_handle *intr_handle,
			      const char *name, int size)
{
  return 0;
}

static_always_inline int
cnxk_plt_intr_vec_list_index_set (struct cnxk_plt_pci_intr_handle *intr_handle,
				  int index, int vec)
{
  return 0;
}

static_always_inline void
cnxk_plt_intr_vec_list_free (struct cnxk_plt_pci_intr_handle *intr_handle)
{
  return;
}

static_always_inline int
cnxk_plt_intr_disable (const struct cnxk_plt_pci_intr_handle *intr_handle)
{
  CNXK_UNIMPLEMENTED ();
  return 0;
}

static_always_inline int
cnxk_plt_intr_callback_register (
  const struct cnxk_plt_pci_intr_handle *intr_handle,
  cnxk_plt_pci_intr_callback_fn cb, void *cb_arg)
{
  CNXK_UNIMPLEMENTED ();
  return 0;
}

static_always_inline int
cnxk_plt_intr_callback_unregister (
  const struct cnxk_plt_pci_intr_handle *intr_handle,
  cnxk_plt_pci_intr_callback_fn cb_fn, void *cb_arg)
{
  CNXK_UNIMPLEMENTED ();
  return 0;
}

static_always_inline int
cnxk_plt_thread_is_intr (void)
{
  return 1;
}

static_always_inline int
cnxk_pltarm_set (u64 us, cnxk_plt_pci_alarm_callback cb_fn, void *cb_arg)
{
  CNXK_UNIMPLEMENTED ();
  return 0;
}

static_always_inline int
cnxk_pltarm_cancel (cnxk_plt_pci_alarm_callback cb_fn, void *cb_arg)
{
  CNXK_UNIMPLEMENTED ();
  return 0;
}

static_always_inline size_t
cnxk_plt_strlcpy (char *dst, const char *src, size_t size)
{
  /* strlcpy needs bsd-dev package */
  return snprintf (dst, size, "%s", src);
}

static_always_inline u32
cnxk_plt_read32_relaxed (const volatile void *addr)
{
  return *(const volatile u32 *) addr;
}

static_always_inline void
cnxk_plt_write32_relaxed (u32 value, volatile void *addr)
{
  *(volatile u32 *) addr = value;
}

static_always_inline u64
cnxk_plt_read64_relaxed (const volatile void *addr)
{
  return *(const volatile u64 *) addr;
}

static_always_inline void
cnxk_plt_write64_relaxed (u64 value, volatile void *addr)
{
  *(volatile u64 *) addr = value;
}

static_always_inline void
cnxk_plt_delay_ms (unsigned msec)
{
  usleep (msec * 1e3);
}

static_always_inline void
cnxk_plt_delay_us (unsigned usec)
{
  usleep (usec);
}

static_always_inline i32
cnxk_plt_pci_read_config (struct cnxk_plt_pci_device *dev, u16 *dst, u32 len,
			  u32 offset)
{
  vlib_main_t *vm;
  clib_error_t *error;
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev->vnet_dev);

  vm = vlib_get_main ();
  error = vlib_pci_read_write_config (vm, h, VLIB_READ, offset, dst, len);
  if (error)
    {
      clib_error_report (error);
      return -1;
    }

  return len;
}

static_always_inline u32
cnxk_plt_pci_config_find_capability (struct cnxk_plt_pci_device *dev, u32 cap)
{
  return 0;
}

static_always_inline int
cnxk_plt_sysfs_value_parse (const char *filename, unsigned long *val)
{
  char buf[BUFSIZ];
  char *end = NULL;
  FILE *f;
  int ret = 0;

  f = fopen (filename, "r");
  if (f == NULL)
    {
      plt_err ("Cannot open sysfs entry %s", filename);
      return -1;
    }

  if (fgets (buf, sizeof (buf), f) == NULL)
    {
      plt_err ("Cannot read sysfs entry %s", filename);
      ret = -1;
      goto close_file;
    }
  *val = strtoul (buf, &end, 0);
  if ((buf[0] == '\0') || (end == NULL) || (*end != '\n'))
    {
      plt_err ("Cannot parse sysfs entry %s", filename);
      ret = -1;
      goto close_file;
    }
close_file:
  fclose (f);
  return ret;
}

#endif /* included_onp_drv_roc_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
