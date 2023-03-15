/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifdef __x86_64__

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/mask_compare.h>

__test_funct_fn void
wrapper (u8 *dst, u8 *src, uword n)
{
  clib_memcpy_x86_64 (dst, src, n);
}

/* clang-format off */
#define foreach_const_n \
  _(1) _(2) _(3) _(4) _(5) _(6) _(7) _(8) _(9) _(10) _(11) _(12) _(13) _(14)  \
  _(15) _(16) _(17) _(18) _(19) _(20) _(21) _(22) _(23) _(24) _(25) _(26)     \
  _(27) _(28) _(29) _(30) _(31) _(32) _(33) _(34) _(35) _(36) _(37) _(38)     \
  _(39) _(40) _(41) _(42) _(43) _(44) _(45) _(46) _(47) _(48) _(49) _(50)     \
  _(51) _(52) _(53) _(54) _(55) _(56) _(57) _(58) _(59) _(60) _(61) _(62)     \
  _(63) _(64) _(65) _(66) _(67) _(68) _(69) _(70) _(71) _(72) _(73) _(74)     \
  _(75) _(76) _(77) _(78) _(79) _(80) _(81) _(82) _(83) _(84) _(85) _(86)     \
  _(87) _(88) _(89) _(90) _(91) _(92) _(93) _(94) _(95) _(96) _(97) _(98)     \
  _(99) _(100) _(101) _(102) _(103) _(104) _(105) _(106) _(107) _(108)        \
  _(109) _(110) _(111) _(112) _(113) _(114) _(115) _(116) _(117) _(118)       \
  _(119) _(120) _(121) _(122) _(123) _(124) _(125) _(126) _(127) _(128)       \
  _(129) _(130) _(131) _(132) _(133) _(134) _(135) _(136) _(137) _(138)       \
  _(139) _(140) _(141) _(142) _(143) _(144) _(145) _(146) _(147) _(148)       \
  _(149) _(150) _(151) _(152) _(153) _(154) _(155) _(156) _(157) _(158)       \
  _(159) _(160) _(161) _(162) _(163) _(164) _(165) _(166) _(167) _(168)       \
  _(169) _(170) _(171) _(172) _(173) _(174) _(175) _(176) _(177) _(178)       \
  _(179) _(180) _(181) _(182) _(183) _(184) _(185) _(186) _(187) _(188)       \
  _(189) _(190) _(191) _(192) _(193) _(194) _(195) _(196) _(197) _(198)       \
  _(199) _(200) _(201) _(202) _(203) _(204) _(205) _(206) _(207) _(208)       \
  _(209) _(210) _(211) _(212) _(213) _(214) _(215) _(216) _(217) _(218)       \
  _(219) _(220) _(221) _(222) _(223) _(224) _(225) _(226) _(227) _(228)       \
  _(229) _(230) _(231) _(232) _(233) _(234) _(235) _(236) _(237) _(238)       \
  _(239) _(240) _(241) _(242) _(243) _(244) _(245) _(246) _(247) _(248)       \
  _(249) _(250) _(251) _(252) _(253) _(254) _(255)
/* clang-format on */

#define _(n)                                                                  \
  static __clib_noinline void wrapper##n (u8 *dst, u8 *src)                   \
  {                                                                           \
    clib_memcpy_x86_64 (dst, src, n);                                         \
  }

foreach_const_n;
#undef _

typedef void (const_fp_t) (u8 *dst, u8 *src);
typedef struct
{
  u16 len;
  const_fp_t *fp;
} counst_test_t;

static counst_test_t const_tests[] = {
#define _(n) { .fp = wrapper##n, .len = n },
  foreach_const_n
#undef _
};

#define MAX_LEN 1024

static clib_error_t *
validate_one (clib_error_t *err, u8 *d, u8 *s, u16 n, u8 off, int is_const)
{
  for (int i = 0; i < n; i++)
    if (d[i] != s[i])
      return clib_error_return (err,
				"memcpy error at position %d "
				"(n = %u, off = %u, expected 0x%02x "
				"found 0x%02x%s)",
				i, n, off, s[i], d[i],
				is_const ? ", const" : "");
  for (int i = -64; i < 0; i++)
    if (d[i] != 0xfe)
      return clib_error_return (err,
				"buffer underrun at position %d "
				"(n = %u, off = %u, expected 0xfe "
				"found 0x%02x%s)",
				i, n, off, d[i], is_const ? ", const" : "");
  for (int i = n; i < n + 64; i++)
    if (d[i] != 0xfe)
      return clib_error_return (err,
				"buffer overrun at position %d "
				"(n = %u, off = %u, expected 0xfe "
				"found 0x%02x%s)",
				i, n, off, d[i], is_const ? ", const" : "");
  return err;
}

static clib_error_t *
test_clib_memcpy_x86_64 (clib_error_t *err)
{
  u8 src[MAX_LEN + 192];
  u8 dst[MAX_LEN + 128];

  for (int i = 0; i < ARRAY_LEN (src); i++)
    src[i] = i & 0x7f;

  for (int j = 0; j < ARRAY_LEN (const_tests); j++)
    {
      u8 *d = dst + 64;
      u8 *s = src + 64;
      u16 n = const_tests[j].len;

      for (int i = 0; i < 128 + n; i++)
	dst[i] = 0xfe;
      const_tests[j].fp (d, s);
      if ((err = validate_one (err, d, s, n, 0, /* is_const */ 1)))
	return err;
    }

  for (u16 n = 1; n <= MAX_LEN; n++)
    {
      for (int off = 0; off < 64; off += 7)
	{
	  u8 *d = dst + 64 + off;
	  u8 *s = src + 64;

	  for (int i = 0; i < 128 + n + off; i++)
	    dst[i] = 0xfe;

	  wrapper (d, s, n);

	  if ((err = validate_one (err, d, s, n, off, /* is_const */ 0)))
	    return err;
	}
    }
  return err;
}

REGISTER_TEST (clib_memcpy_x86_64) = {
  .name = "clib_memcpy_x86_64",
  .fn = test_clib_memcpy_x86_64,
};
#endif
