


#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <acl/sparse_bitmap.h>


void
sparse_bitmap_test (vlib_main_t * vm)
{
  clib_warning ("Sparse bitmap test");
  sbitmap_t *sb0 = 0;
  sbitmap_t *sb1 = 0;
  sbitmap_t *sb3 = 0;
  clib_warning ("empty bitmap: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 0);
  clib_warning ("bit set: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 2);
  clib_warning ("bit set: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 22);
  clib_warning ("bit set: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 39);
  clib_warning ("2nd bit set: %U", format_sbitmap_hex, sb0);
  // sbm_clear_bit(&sb0, 39); clib_warning("2nd bit cleared: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 339);
  clib_warning ("3rd bit set: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 319);
  clib_warning ("4th bit set: %U", format_sbitmap_hex, sb0);
  sbm_clear_bit (&sb0, 319);
  clib_warning ("4th bit cleared: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 318);
  clib_warning ("5th bit set: %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb0, 230);
  clib_warning ("6th bit set (and): %U", format_sbitmap_hex, sb0);
  sbm_set_bit (&sb1, 319);
  sbm_set_bit (&sb1, 230);
  sbm_set_bit (&sb1, 39);
  sbm_set_bit (&sb1, 78);
  clib_warning ("bitstring1 *(or): (%08x) %U", sb1, format_sbitmap_hex, sb1);

  sbitmap_t *sb2 = 0;
  sbm_and (&sb2, sb0, sb1);
  clib_warning ("bitstring2: %U", format_sbitmap_hex, sb2);

  sbm_set_bit (&sb3, 230);
  clib_warning ("bitstring3: %U", format_sbitmap_hex, sb3);

  sbitmap_t *sb4 = 0;
  sbm_and (&sb2, sb2, sb3);
  clib_warning ("bitstring2 *(or): %U", format_sbitmap_hex, sb2);
  sbm_and_or (&sb4, sb0, sb1, sb2);
  clib_warning ("bitstring4: %U", format_sbitmap_hex, sb4);
  sbm_or (&sb4, sb1, sb2);
  clib_warning ("bitstring4 or src: %U", format_sbitmap_hex, sb4);
  sbm_or (&sb4, sb0, sb1);
  clib_warning ("bitstring4 andor src: %U", format_sbitmap_hex, sb4);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
