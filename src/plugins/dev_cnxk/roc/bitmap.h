/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_roc_bitmap_h
#define included_onp_drv_roc_bitmap_h

typedef struct cnxk_plt_bitmap
{
  uword *bitmap;
} cnxk_plt_bitmap_t;

#define plt_bitmap			cnxk_plt_bitmap
#define plt_bitmap_get_memory_footprint cnxk_plt_bitmap_get_mem_footprint
#define plt_bitmap_init			cnxk_plt_bitmap_init
#define plt_bitmap_reset		cnxk_plt_bitmap_reset
#define plt_bitmap_free			cnxk_plt_bitmap_free
#define plt_bitmap_clear		cnxk_plt_bitmap_clear
#define plt_bitmap_set			cnxk_plt_bitmap_set
#define plt_bitmap_get			cnxk_plt_bitmap_get
#define plt_bitmap_scan_init		cnxk_plt_bitmap_scan_init
#define plt_bitmap_scan			cnxk_plt_bitmap_scan

static_always_inline u32
cnxk_plt_bitmap_get_mem_footprint (u32 n_bits)
{
  /* In bytes, will be freed in bitmap init call */
  return n_bits;
}

static_always_inline cnxk_plt_bitmap_t *
cnxk_plt_bitmap_init (u32 n_bits, u8 *mem, u32 mem_size)
{
  cnxk_plt_bitmap_t *bmp;

  /*
   * TODO:
   * mem leak, need to free original mem pointer
   * clib_mem_free (mem);
   */
  bmp = vec_new (cnxk_plt_bitmap_t, 1);
  clib_bitmap_alloc (bmp->bitmap, n_bits);
  return bmp;
}

static_always_inline void
cnxk_plt_bitmap_reset (cnxk_plt_bitmap_t *bmp)
{
  clib_bitmap_zero (bmp->bitmap);
}

static_always_inline void
cnxk_plt_bitmap_clear (cnxk_plt_bitmap_t *bmp, u32 pos)
{
  clib_bitmap_set (bmp->bitmap, pos, 0);
}

static_always_inline int
cnxk_plt_bitmap_free (cnxk_plt_bitmap_t *bmp)
{
  clib_bitmap_free (bmp->bitmap);
  vec_free (bmp);
  return 0;
}

static_always_inline u64
cnxk_plt_bitmap_get (cnxk_plt_bitmap_t *bmp, u32 pos)
{
  return clib_bitmap_get (bmp->bitmap, pos);
}

static_always_inline void
cnxk_plt_bitmap_set (cnxk_plt_bitmap_t *bmp, u32 pos)
{
  clib_bitmap_set (bmp->bitmap, pos, 1);
}

static_always_inline void
cnxk_plt_bitmap_scan_init (cnxk_plt_bitmap_t *bmp)
{
  return;
}

static_always_inline int
cnxk_plt_bitmap_scan (cnxk_plt_bitmap_t *bmp, u32 *pos, u64 *slab)
{
  if (clib_bitmap_is_zero (bmp->bitmap))
    return 0;

  *pos = clib_bitmap_last_set (bmp->bitmap);

  return 1;
}

#endif /* included_onp_drv_roc_bitmap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
