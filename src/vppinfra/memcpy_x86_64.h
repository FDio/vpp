
#include <vppinfra/clib.h>

static inline void
clib_memcpy_const_le32 (u8 *dst, u8 *src, size_t n)
{
  switch (n)
    {
    case 1:
      *(u8 *) dst = *(u8 *) src;
      break;
    case 2:
      *(u16u *) dst = *(u16u *) src;
      break;
    case 3:
      *(u16u *) dst = *(u16u *) src;
      *((u8 *) dst + 2) = *((u8 *) src + 2);
      break;
    case 4:
      *(u32u *) dst = *(u32u *) src;
      break;
    case 5:
      *(u32u *) dst = *(u32u *) src;
      *((u8 *) dst + 4) = *((u8 *) src + 4);
      break;
    case 6:
      *(u32u *) dst = *(u32u *) src;
      *((u16u *) dst + 2) = *((u16u *) src + 2);
      break;
    case 7:
      *(u32u *) dst = *(u32u *) src;
      *((u32u *) (dst + 3)) = *((u32u *) (src + 3));
      break;
    case 8:
      *(u64u *) dst = *(u64u *) src;
      break;
    case 9:
      *(u64u *) dst = *(u64u *) src;
      *(dst + 8) = *(src + 8);
      break;
    case 10:
      *(u64u *) dst = *(u64u *) src;
      *((u16u *) (dst + 8)) = *((u16u *) (src + 8));
      break;
    case 11:
    case 12:
      *(u64u *) dst = *(u64u *) src;
      *((u32u *) (dst + n - 4)) = *((u32u *) (src + n - 4));
      break;
    case 13:
    case 14:
    case 15:
      *(u64u *) dst = *(u64u *) src;
      *((u64u *) (dst + n - 8)) = *((u64u *) (src + n - 8));
      break;
    case 16:
      *(u8x16u *) dst = *(u8x16u *) src;
      break;
    case 17:
      *(u8x16u *) dst = *(u8x16u *) src;
      *(dst + 16) = *(src + 16);
      break;
    case 18:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u16u *) (dst + 16)) = *((u16u *) (src + 16));
      break;
    case 20:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u32u *) (dst + 16)) = *((u32u *) (src + 16));
      break;
    case 24:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u64u *) (dst + 16)) = *((u64u *) (src + 16));
      break;
    default:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u8x16u *) (dst + n - 16)) = *((u8x16u *) (src + n - 16));
      break;
    }
}

static inline void
clib_memcpy_const_le64 (u8 *dst, u8 *src, size_t n)
{
  if (n < 32)
    {
      clib_memcpy_const_le32 (dst, src, n);
      return;
    }

#if defined(CLIB_HAVE_VEC256)
  switch (n)
    {
    case 32:
      *(u8x32u *) dst = *(u8x32u *) src;
      break;
    case 33:
      *(u8x32u *) dst = *(u8x32u *) src;
      *(dst + 32) = *(src + 32);
      break;
    case 34:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u16u *) (dst + 32)) = *((u16u *) (src + 32));
      break;
    case 36:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u32u *) (dst + 32)) = *((u32u *) (src + 32));
      break;
    case 40:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u64u *) (dst + 32)) = *((u64u *) (src + 32));
      break;
    case 48:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u8x16u *) (dst + 32)) = *((u8x16u *) (src + 32));
      break;
    default:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u8x32u *) (dst + n - 32)) = *((u8x32u *) (src + n - 32));
      break;
    }
#else
  while (n > 31)
    {
      *(u8x16u *) dst = *(u8x16u *) src;
      dst += 16;
      src += 16;
      n -= 16;
    }
  clib_memcpy_const_le32 (dst, src, n);
#endif
}

static inline void
clib_memcpy_const_le128 (u8 *dst, u8 *src, size_t n)
{
  if (n < 64)
    {
      clib_memcpy_const_le64 (dst, src, n);
      return;
    }

#if defined(CLIB_HAVE_VEC512)
  switch (n)
    {
    case 64:
      *(u8x64u *) dst = *(u8x64u *) src;
      break;
    case 65:
      *(u8x64u *) dst = *(u8x64u *) src;
      *(dst + 64) = *(src + 64);
      break;
    case 66:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u16u *) (dst + 64)) = *((u16u *) (src + 64));
      break;
    case 68:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u32u *) (dst + 64)) = *((u32u *) (src + 64));
      break;
    case 72:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u64u *) (dst + 64)) = *((u64u *) (src + 64));
      break;
    case 80:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x16u *) (dst + 64)) = *((u8x16u *) (src + 64));
      break;
    case 96:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x32u *) (dst + 64)) = *((u8x32u *) (src + 64));
      break;
    default:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x64u *) (dst + n - 64)) = *((u8x64u *) (src + n - 64));
      break;
    }
#elif defined(CLIB_HAVE_VEC256)
  while (n > 63)
    {
      *(u8x32u *) dst = *(u8x32u *) src;
      dst += 32;
      src += 32;
      n -= 32;
    }
  clib_memcpy_const_le64 (dst, src, n);
#else
  while (n > 31)
    {
      *(u8x16u *) dst = *(u8x16u *) src;
      dst += 16;
      src += 16;
      n -= 16;
    }
  clib_memcpy_const_le32 (dst, src, n);
#endif
}
