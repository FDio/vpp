/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#if defined(__AES__) || defined(__ARM_FEATURE_CRYPTO)
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crypto/aes_ctr.h>

static const struct
{
  char *name;
  const u8 *pt, *key, *ct, *iv;
  u32 data_len;
} test_cases128[] = {
  /* test cases */
  { .name = "RFC3686 Test Vector #1",
    .key = (const u8[16]){ 0xae, 0x68, 0x52, 0xf8, 0x12, 0x10, 0x67, 0xcc,
			   0x4b, 0xf7, 0xa5, 0x76, 0x55, 0x77, 0xf3, 0x9e },
    .iv = (const u8[16]){ 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },

    .pt = (const u8 *) "Single block msg",
    .ct = (const u8[16]){ 0xe4, 0x09, 0x5d, 0x4f, 0xb7, 0xa7, 0xb3, 0x79, 0x2d,
			  0x61, 0x75, 0xa3, 0x26, 0x13, 0x11, 0xb8 },
    .data_len = 16 },
  { .name = "RFC3686 Test Vector #2",
    .key = (const u8[16]){ 0x7e, 0x24, 0x06, 0x78, 0x17, 0xfa, 0xe0, 0xd7,
			   0x43, 0xd6, 0xce, 0x1f, 0x32, 0x53, 0x91, 0x63 },
    .iv = (const u8[16]){ 0x00, 0x6c, 0xb6, 0xdb, 0xc0, 0x54, 0x3b, 0x59, 0xda,
			  0x48, 0xd9, 0x0b, 0x00, 0x00, 0x00, 0x01 },
    .pt = (const u8[32]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
    .ct = (const u8[32]){ 0x51, 0x04, 0xa1, 0x06, 0x16, 0x8a, 0x72, 0xd9,
			  0x79, 0x0d, 0x41, 0xee, 0x8e, 0xda, 0xd3, 0x88,
			  0xeb, 0x2e, 0x1e, 0xfc, 0x46, 0xda, 0x57, 0xc8,
			  0xfc, 0xe6, 0x30, 0xdf, 0x91, 0x41, 0xbe, 0x28 },
    .data_len = 32 },
  { .name = "RFC3686 Test Vector #3",
    .key = (const u8[16]){ 0x76, 0x91, 0xbe, 0x03, 0x5e, 0x50, 0x20, 0xa8,
			   0xac, 0x6e, 0x61, 0x85, 0x29, 0xf9, 0xa0, 0xdc },
    .iv = (const u8[16]){ 0x00, 0xe0, 0x01, 0x7b, 0x27, 0x77, 0x7f, 0x3f, 0x4a,
			  0x17, 0x86, 0xf0, 0x00, 0x00, 0x00, 0x01 },
    .pt =
      (const u8[36]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
		      0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23 },
    .ct =
      (const u8[36]){ 0xc1, 0xcf, 0x48, 0xa8, 0x9f, 0x2f, 0xfd, 0xd9, 0xcf,
		      0x46, 0x52, 0xe9, 0xef, 0xdb, 0x72, 0xd7, 0x45, 0x40,
		      0xa4, 0x2b, 0xde, 0x6d, 0x78, 0x36, 0xd5, 0x9a, 0x5c,
		      0xea, 0xae, 0xf3, 0x10, 0x53, 0x25, 0xb2, 0x07, 0x2f },
    .data_len = 36 },
}, test_cases192[] = {
  { .name = "RFC3686 Test Vector #4",
    .key = (const u8[24]){ 0x16, 0xaf, 0x5b, 0x14, 0x5f, 0xc9, 0xf5, 0x79,
			   0xc1, 0x75, 0xf9, 0x3e, 0x3b, 0xfb, 0x0e, 0xed,
			   0x86, 0x3d, 0x06, 0xcc, 0xfd, 0xb7, 0x85, 0x15 },
    .iv = (const u8[16]){ 0x00, 0x00, 0x00, 0x48, 0x36, 0x73, 0x3c, 0x14, 0x7d,
			  0x6d, 0x93, 0xcb, 0x00, 0x00, 0x00, 0x01 },
    .pt = (const u8[16]){ 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x62, 0x6c,
			  0x6f, 0x63, 0x6b, 0x20, 0x6d, 0x73, 0x67 },
    .ct = (const u8[16]){ 0x4b, 0x55, 0x38, 0x4f, 0xe2, 0x59, 0xc9, 0xc8, 0x4e,
			  0x79, 0x35, 0xa0, 0x03, 0xcb, 0xe9, 0x28 },
    .data_len = 16 },
  { .name = "RFC3686 Test Vector #5",
    .key = (const u8[24]){ 0x7c, 0x5c, 0xb2, 0x40, 0x1b, 0x3d, 0xc3, 0x3c,
			   0x19, 0xe7, 0x34, 0x08, 0x19, 0xe0, 0xf6, 0x9c,
			   0x67, 0x8c, 0x3d, 0xb8, 0xe6, 0xf6, 0xa9, 0x1a },
    .iv = (const u8[16]){ 0x00, 0x96, 0xb0, 0x3b, 0x02, 0x0c, 0x6e, 0xad, 0xc2,
			  0xcb, 0x50, 0x0d, 0x00, 0x00, 0x00, 0x01 },
    .pt = (const u8[32]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
    .ct = (const u8[32]){ 0x45, 0x32, 0x43, 0xfc, 0x60, 0x9b, 0x23, 0x32,
			  0x7e, 0xdf, 0xaa, 0xfa, 0x71, 0x31, 0xcd, 0x9f,
			  0x84, 0x90, 0x70, 0x1c, 0x5a, 0xd4, 0xa7, 0x9c,
			  0xfc, 0x1f, 0xe0, 0xff, 0x42, 0xf4, 0xfb, 0x00 },
    .data_len = 32 },
  { .name = "RFC3686 Test Vector #6",
    .key = (const u8[24]){ 0x02, 0xBF, 0x39, 0x1E, 0xE8, 0xEC, 0xB1, 0x59,
			   0xB9, 0x59, 0x61, 0x7B, 0x09, 0x65, 0x27, 0x9B,
			   0xF5, 0x9B, 0x60, 0xA7, 0x86, 0xD3, 0xE0, 0xFE },
    .iv = (const u8[16]){ 0x00, 0x07, 0xBD, 0xFD, 0x5C, 0xBD, 0x60, 0x27, 0x8D,
			  0xCC, 0x09, 0x12, 0x00, 0x00, 0x00, 0x01 },
    .pt =
      (const u8[36]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
		      0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
		      0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23 },
    .ct =
      (const u8[36]){ 0x96, 0x89, 0x3F, 0xC5, 0x5E, 0x5C, 0x72, 0x2F, 0x54,
		      0x0B, 0x7D, 0xD1, 0xDD, 0xF7, 0xE7, 0x58, 0xD2, 0x88,
		      0xBC, 0x95, 0xC6, 0x91, 0x65, 0x88, 0x45, 0x36, 0xC8,
		      0x11, 0x66, 0x2F, 0x21, 0x88, 0xAB, 0xEE, 0x09, 0x35 },
    .data_len = 36 },

}, test_cases256[] = {
  { .name = "RFC3686 Test Vector #7",
    .key = (const u8[32]){ 0x77, 0x6b, 0xef, 0xf2, 0x85, 0x1d, 0xb0, 0x6f,
			   0x4c, 0x8a, 0x05, 0x42, 0xc8, 0x69, 0x6f, 0x6c,
			   0x6a, 0x81, 0xaf, 0x1e, 0xec, 0x96, 0xb4, 0xd3,
			   0x7f, 0xc1, 0xd6, 0x89, 0xe6, 0xc1, 0xc1, 0x04 },
    .iv = (const u8[16]){ 0x00, 0x00, 0x00, 0x60, 0xdb, 0x56, 0x72, 0xc9, 0x7a,
			  0xa8, 0xf0, 0xb2, 0x00, 0x00, 0x00, 0x01 },
    .pt = (const u8 *) "Single block msg",
    .ct = (const u8[16]){ 0x14, 0x5a, 0xd0, 0x1d, 0xbf, 0x82, 0x4e, 0xc7, 0x56,
			  0x08, 0x63, 0xdc, 0x71, 0xe3, 0xe0, 0xc0 },
    .data_len = 16 },
  { .name = "RFC3686 Test Vector #8",
    .key = (const u8[32]){ 0xf6, 0xd6, 0x6d, 0x6b, 0xd5, 0x2d, 0x59, 0xbb,
			   0x07, 0x96, 0x36, 0x58, 0x79, 0xef, 0xf8, 0x86,
			   0xc6, 0x6d, 0xd5, 0x1a, 0x5b, 0x6a, 0x99, 0x74,
			   0x4b, 0x50, 0x59, 0x0c, 0x87, 0xa2, 0x38, 0x84 },
    .iv = (const u8[16]){ 0x00, 0xfa, 0xac, 0x24, 0xc1, 0x58, 0x5e, 0xf1, 0x5a,
			  0x43, 0xd8, 0x75, 0x00, 0x00, 0x00, 0x01 },
    .pt = (const u8[32]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
    .ct = (const u8[32]){ 0xf0, 0x5e, 0x23, 0x1b, 0x38, 0x94, 0x61, 0x2c,
			  0x49, 0xee, 0x00, 0x0b, 0x80, 0x4e, 0xb2, 0xa9,
			  0xb8, 0x30, 0x6b, 0x50, 0x8f, 0x83, 0x9d, 0x6a,
			  0x55, 0x30, 0x83, 0x1d, 0x93, 0x44, 0xaf, 0x1c },
    .data_len = 32 },
  { .name = "RFC3686 Test Vector #9",
    .key = (const u8[32]){ 0xff, 0x7a, 0x61, 0x7c, 0xe6, 0x91, 0x48, 0xe4,
			   0xf1, 0x72, 0x6e, 0x2f, 0x43, 0x58, 0x1d, 0xe2,
			   0xaa, 0x62, 0xd9, 0xf8, 0x05, 0x53, 0x2e, 0xdf,
			   0xf1, 0xee, 0xd6, 0x87, 0xfb, 0x54, 0x15, 0x3d },
    .iv = (const u8[16]){ 0x00, 0x1c, 0xc5, 0xb7, 0x51, 0xa5, 0x1d, 0x70, 0xa1,
			  0xc1, 0x11, 0x48, 0x00, 0x00, 0x00, 0x01 },
    .pt =
      (const u8[36]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
		      0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23 },
    .ct =
      (const u8[36]){ 0xeb, 0x6c, 0x52, 0x82, 0x1d, 0x0b, 0xbb, 0xf7, 0xce,
		      0x75, 0x94, 0x46, 0x2a, 0xca, 0x4f, 0xaa, 0xb4, 0x07,
		      0xdf, 0x86, 0x65, 0x69, 0xfd, 0x07, 0xf4, 0x8c, 0xc0,
		      0xb5, 0x83, 0xd6, 0x07, 0x1f, 0x1e, 0xc0, 0xe6, 0xb8 },
    .data_len = 36 }
};

#define MAX_TEST_DATA_LEN 256

#define INC_TEST_BYTES (256 * 16 + 1)

static u8 inc_key128[] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static u8 inc_iv[] = {
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static u64 inc_ct128[] = {
  0xb77a659c70dd8dec, 0xebaf93e67e1cdbfa, 0x744766732f6e3a26,
  0xb16d4de0cc6db900, 0x6811ac5c5be10d4a, 0x6b42973b30e29d96,
  0xf1aec4c4ac0badd8, 0xc1955129e00b33ec, 0x49d7cf50bb054cf0,
  0x4deb06dcdc7a21b8, 0xa257b4190916c808, 0x44b7d421c38b934b,
  0x9e4dbb2d1aceb85b, 0x2d1c952f53c6000d, 0x7e25b633f3bceb0d,
  0xcee9f88cd3c2236d, 0x10ce6bc4a53b1d37, 0xb4783ea69ebc261d,
  0x7f732c19e5fdd3ea, 0xb253d0ebd5522c84, 0x7925888c44ef010d,
  0xba213ea62e7ec7f0, 0x239e0466520393fd, 0x8cde31681d451842,
  0x20b8270d3c5c1bc5, 0x3e56c37a1d573ebe, 0xc4fdb0bb491cf04e,
  0x29c9a4f92d7b12da, 0x50c8a51f05b6f704, 0x3cf0f4071c2098fa,
  0xb0842470bd8c6fdd, 0x86dd40fdc9640190, 0xe4a6184230ee4f6c,
  0x0e2a69261819535e, 0xbdb62571c80aaa39, 0x24a0dc5eafd33f3a,
  0x830599f37869c6ac, 0xf7049ae1b8e5c0dd, 0x7c9dd8d4405d2050,
  0x0e91382b1dace623, 0xf2b62e26f4133673, 0xa9216257693afdab,
  0x2a26df863fb6e980, 0x85e600421c395c83, 0xd5a521016a175cb3,
  0x5ef31ae51f7f2f7b, 0xc6ff491d0d6f74d4, 0x16b0e60ac13156d3,
  0xd49e0025d5ec1e4b, 0x987c4eff196cd64e, 0xa163915e80892b07,
  0x69ab0084052d574a, 0x8017caa649d22bdb, 0xf5eb130f0df2c49a,
  0xe2ced8f88537e9ea, 0xdaaff5e845cff681, 0xbd22ac46dd219c7a,
  0x1b963af4641e7cf7, 0xe70e7d5b76f88573, 0x39703f5e2db84937,
  0x8a1514af42bf3c96, 0x7f51d78b7d3971a6, 0x437a651ef9f08c08,
  0x69fd3712ccdfd843, 0xd8204939e67dad48, 0x71035fc942194251,
  0x703d964c7525bb2a, 0xe2166e50e1892d94, 0xbe8034b11f6a5a9f,
  0x954e4d74c3a9e105, 0x19e077bf00e5186a, 0x7aee46c4b5d4cbf1,
  0xfd7dedd15a3e7d35, 0x4ba1c4b76cb93f57, 0xb2e94cffbb82f098,
  0x078b04fcebc1fafc, 0x923edcc8600018b2, 0xc018169aba42ff11,
  0x0e4f91e46db01bf8, 0x7b5d2b322371e9fa, 0x8e94284632dd300b,
  0x80a3d93ce61c2f13, 0x445d2fb83ecfef73, 0xe1279d639bcd26c9,
  0xbd1865ba653ce114, 0x0316cfe3227bfb2a, 0xddc80c63d53878db,
  0xc91a2f5fedf4a51a, 0xce408a5275b0271f, 0x59a0abc34619018e,
  0xa215c590ad1afb21, 0xe3b096d42fc03598, 0x7cada064ab4f4997,
  0x699be0e57d76e47f, 0x235151411eee9cbd, 0xbbc688f0eaf896cd,
  0x4e78715341f9299d, 0x9f85d76bf99ef2a4, 0x15110ceff4a6040b,
  0x9feed36ff4566060, 0x4833ea7d66a0c572, 0x94c7edbdf2169d59,
  0xb413d116c6e771f1, 0x9a4b6e78167f4c66, 0x42d3f993c8aaee27,
  0xd16783a8c4e57558, 0xb1d7a074dd67339e, 0x97a164444f97adc2,
  0xc15a08d61628e5f3, 0x8767e41e04eb96a2, 0xbb28953ed0eae183,
  0xc0bab4e80ed8cc6e, 0x1ac34b5a5c4010f8, 0x0bc3b7d9db1775b7,
  0x565dead595b98969, 0x0fc03a3cfb656014, 0xdb9098b924a92926,
  0xe2786bc431c1f39a, 0xf8a0bf4fffb78d10, 0xd76161fe1ae71851,
  0xced33ea693cedbb4, 0xef13034da5529a1b, 0xd71081cadbbff0ac,
  0x1873eb643e857392, 0xf6f7c30284ffecb0, 0x93ded259d35eb6fe,
  0xf872980774f6e5ef, 0xd457c8ed22d5bc3f, 0x75d907e2a6bcced2,
  0xcfd3dceb8d7a79ba, 0xaeed2ff2fc0872bb, 0xb5fc72005d2eb168,
  0x850e0e0757274665, 0xab7e5da576c706ec, 0xf1df1ba9a972a4ca,
  0xe81d430b4f54adf9, 0x788f3d8655ba79bb, 0xf5990db3557bbf8c,
  0x1cacafc47729252c, 0x7581b4d6f3b83d9b, 0x94185dcdb0b0c4cd,
  0x3596e687f4b9f4ed, 0xb9462442134b804d, 0xdab188808726fec6,
  0xfe10831e8824d4c5, 0x000c641ed4c93be7, 0x2525ee781608b1ea,
  0x2b32469d51104097, 0x73a09c6ea117aea9, 0x8506dcdec8ade0be,
  0xf9f9fa553cac7285, 0x34b24f100086b974, 0xd42fa88547ade8e7,
  0xfd0bb8ce9a5f8e14, 0x15df9966c6a3e433, 0xf6696aafaae89cd6,
  0x3d521a9d1a0087e1, 0xe18ca6b8e94701f0, 0x8a4660e26a77965e,
  0xc74fcdf41bf4aa20, 0x292a356d0b670157, 0x36ff3344a9eee4ea,
  0xd76b051d6251a14b, 0xa9e09f1bacd1e30f, 0xae47cb95f95a8831,
  0x58b85ac7c98537ec, 0x9e30f1be05719bd2, 0x94772e6b56fc1380,
  0xbe94026a4a89b783, 0x7a7ffb61daa5ac60, 0x2f7beafcc5e9ac8a,
  0xfa33f37edc57e94c, 0x230c3582fb412093, 0xdeec806ecc4fa3c4,
  0xc7ff8876a31edd76, 0x6d0500f4ccd1bb20, 0xf1d0bef759b81b6c,
  0x138b1d39533379b7, 0xece52f84d9f20455, 0x3ed05e391352b9dd,
  0x95600f558d4dea51, 0x1d6b997966e35392, 0x0eeae16905b94e37,
  0x7db2acc242a56ab0, 0xaf347e5598687f51, 0xbf25013db6bddc18,
  0x6d4f106c35f9ee28, 0xc8e90bbe4283ab8c, 0x188cf978f1477dee,
  0x66376bfa3a6d8131, 0xe0ebd6632eb89b24, 0xb9e49d81e9d37f69,
  0xa5cfa3812d530e04, 0x717353523542a27f, 0x0d6669c916ab4d34,
  0x79e741ad592a7bb1, 0x63a7f35584bd3ea5, 0xc0494db2930cbc32,
  0x442bd29d7edd0e49, 0x52ec0bce733f61a0, 0x8bd199bf55bc2b4b,
  0x727ede5583bb859c, 0x9d07eda6e8220df1, 0xebdd7467d7259f15,
  0x8f6035a5dc5f53b1, 0x063a0935630b5f6f, 0xc6e983ec1f08ebe6,
  0xeedc82de2b28e651, 0xe28760013e13ae23, 0x37c078d66ad376a3,
  0xd54a72e88e80926b, 0x5822405e1d688eec, 0xa001e0b0d4a7447f,
  0xfd41f41419d8fd4d, 0x1391d37127a75095, 0x4795d7fb7ad67f17,
  0xa47c05c9b8400a0c, 0x28519cd5e98bba0c, 0x84a72dce8a27d050,
  0xcbee7b3c83d68c5f, 0xab2227b8f5203d3d, 0x3335a393d47ef9ec,
  0xd00b21a2a5dde597, 0xb13d50489ca79216, 0xde1cc721425dda94,
  0x1ddc9863b5b0b8e8, 0xb125481a01dfe1b5, 0x5b331c746c4148db,
  0x8d6729fe30d56f1d, 0xdc413723540aca6f, 0xf08fe55711f8f09b,
  0x98bcde7c09126688, 0xa38c02a0c19d08b0, 0xde8df0683372e31e,
  0x08b4727054d766a0, 0xc13b77c325ae45ed, 0x6e7fe05de6b28d5a,
  0x1794a4f149586b9a, 0x23f5881c699f81b8, 0x355c9d899c0dcfe3,
  0x4319acb92ca33a29, 0x4f3211554c2ecf79, 0x64741347e08aaa2f,
  0x32f89bf1084e0723, 0xb0d5d830b9ae58a6, 0x235170babbd5686f,
  0xaa711d0aff2e9830, 0x4f73229995f82ca2, 0x46565f056bb352ea,
  0x55283776fd729f29, 0xb027c5b67be58718, 0xfa58d8c215d52ef8,
  0xfa1a78f7c7db4b2f, 0x7b2badd9a5a7e810, 0x6c362d97ece0f08a,
  0xff8ad11e7ce377b1, 0xdf5a423e843cbfa0, 0xfa9e70edc9c12d2b,
  0xad745d9146b0b3d9, 0xfc2a590f1ce32b8c, 0x599b34c583449c39,
  0xbcab9517d2bd4eae, 0xa5a7f54890e38bc7, 0xb9700fcb336a049a,
  0xfcfcc2d65956af5f, 0x3887b5f3e5d238d6, 0x0b9bc00a60dd37c6,
  0x09f8d5b6a128fe23, 0x4b33ac26a2a59b5c, 0xfc6e3f30b4b4e108,
  0x1e53d6aa6266bee7, 0x9adf6b4cb3369643, 0xda38dfd6df234f48,
  0x845e61ddc98d3d16, 0x4a0b90d7d115d701, 0x64e1c9619aa777c3,
  0x9dd4b1df006c81f9, 0x71b2b88aea6c679e, 0xb39da7819be759ff,
  0xfdad221790b269bb, 0x741f7955b56d786c, 0x5d724fcce9250a73,
  0x3812aa144730905b, 0xb74986be047e24c4, 0xeebb8aa5ebdcc8a0,
  0x26a0ea4272d5a371, 0x2ff3733c39e92f82, 0x17880beb7b808b30,
  0xe298cf8aa284e39c, 0xd481ff1948d0eef0, 0xed53786d517a1f10,
  0x853ccfe7f1cba481, 0x9ba1707467deb6dc, 0xf1aae1c3190806b3,
  0xb017539bb50b55c4, 0x8809bcc37ac46808, 0x0ae0a3e6e9a6bba5,
  0xf7a5276c2a6df772, 0xaf095d1ceb24d931, 0xaa0f62c5eb44d3a6,
  0x5e9915d18cd09844, 0xcfff6a2edf6cd35f, 0x893ebc1038af747e,
  0xe4360da910f3853a, 0x2097129be26812d5, 0x09d1e31bd3fef181,
  0x37a585c49cff87c5, 0xd94d2b3b1cd97311, 0xa3a2d50de285388a,
  0xf627d8b7298602a0, 0x567f848218395a28, 0x9b4b416995765491,
  0x24388b443fd8730a, 0x5b3a3cc87e225bdb, 0x53a9881d098d520b,
  0xadbc31258140299f, 0x37345aad0c678a3f, 0xc0e24ea3958ef6d8,
  0x18ceff669a144d20, 0x3ce920ab86ab70c7, 0x430c240b5307c1cb,
  0x7240a314d5f7fa9c, 0x4dfaf972d1856f15, 0x76ca74db2ad10515,
  0x607ec82965c620f7, 0xc75f531d7eae4145, 0xe91c86c49c8d84a2,
  0x8becf71fe1e371a7, 0x055bb0206808c289, 0x36dbcec66eabc566,
  0x476f4f1b52c4c856, 0x78bdf9114304e28f, 0x206e8342087ca6e2,
  0xda66f574514e8795, 0x903bcf41830a763f, 0x3a8c03f8bfe8c1ae,
  0xc386671f05740107, 0xda3abc3b566c70ab, 0xe1072ad4ebd4a028,
  0xfe9a6d4c0e8a80ce, 0xeb99eb25a084c442, 0xd34f23f8f279e9f3,
  0xccb189048479b94d, 0xfc6f6d863f74a049, 0xa437f340bfdfed0e,
  0xc84ef9a7139af764, 0xbeb88737819b7d55, 0x5f06fb8f06d6372b,
  0x7ec01ec2f978b4a2, 0x1ad4f2fb9963b46f, 0xae4cdeee5c419652,
  0x51ee340ba106d1dc, 0x93544a6e274cf180, 0x0de0b1abf6e9773a,
  0xb55514c7be768e6a, 0x70a3ee12298c0688, 0x58943a332454b1ee,
  0xe9de88a863b83b29, 0xb99dbf02fc35d6c9, 0x285a09f5583ac480,
  0xd0bf2b79a453c915, 0xb6e140e86dcb97d5, 0x8de0ab74f93a8de1,
  0x70f9bb989ce46c09, 0xd7ea17d64158d923, 0x308e3f8a527d0ff7,
  0xa0fffd413b3a872f, 0xcd35b4b30dfb6587, 0x7ef3ab8b9bd5fbcf,
  0x6149f604d9f355f7, 0x130d9020814780cd, 0x45cb969837f9a147,
  0x88dc31c106a2345e, 0x690da693a3472e6d, 0xe1dc49aaab6d8504,
  0x7749dc54f0a8f838, 0x358a1197921ed6e3, 0x50ae914d7b26c811,
  0x6e0f79b3af64d1ad, 0xec45b7e54c408577, 0x94809242f830a52f,
  0x88e8c0701fd8cd25, 0x21f562f903b85ca7, 0x3f8f1d2cfd57d394,
  0x1f0db9fb1767b393, 0x0504a2b6a6b967d3, 0xf18209ff9dee356b,
  0x4e74343f94f09cff, 0x53107e4bd79b52c1, 0x9c4ab4cdba0f0c2f,
  0xfd085f652a3c3f14, 0xcbd20129e019e573, 0x92d2e7681d64d41b,
  0xfa6c6c50db35a8fd, 0x7dc5177e0cc57261, 0xae3586379eed9e9d,
  0x4ba340964a014d54, 0x57147f7d60a4a5ee, 0x423255e50fec612e,
  0x1c1158e2a2afbace, 0x5e0dd39d591b341f, 0x4e0fff62124939a6,
  0x12e0413146fa5c8d, 0x3a6e0c37d48699a0, 0x9774260521aa490f,
  0xbd0f8ecc2b447c99, 0x556d41deab48dad8, 0x08bd36a5be98bc97,
  0x8bf0c22eb1cb99a0, 0x959954221670e572, 0x05143412beae5a0c,
  0x37246cbdf96ede32, 0xeb05ce52c11ab210, 0xd4e9c130ccd17048,
  0x42cc9b6177b7547b, 0x96d603334e7a85c7, 0x850365d5d2f5adcb,
  0xcfa11346e834516c, 0xfb9e30870be0c7bb, 0xc4d137ab85224e7a,
  0xc7f20e98475c4ab3, 0xaf464d45151fec79, 0xe4ad336a38569bcd,
  0xabd20fbf84b809bd, 0xb3643ed21050862a, 0xfb29924632f30a27,
  0x3f4fd0809492521f, 0xcc9635ff080ba76d, 0xeb679199764753a7,
  0x9df2de103f532b81, 0x83784f41703f0a31, 0x70ba6c249783efba,
  0x93cf542badd6d441, 0x8290f3e7b7fcc9a6, 0xb55485e8fadf4677,
  0xf29c554f7e99c1de, 0x277a3a2d674f10e9, 0xe9a5460c4d87bd2a,
  0x0d8489866023402a, 0x6bd7d212c07df415, 0x8d6194cb592bebc3,
  0xa9747f53b4cd4192, 0x56bd4c4c6373dcb9, 0x3385c9e222966cb2,
  0x234bda6863a4f7fd, 0xebc79b310f06f538, 0x3b7556403468fc38,
  0x9ac05c55de908490, 0x381dba9f8e05fd0e, 0x5e92d1853484e36a,
  0x030782801735585f, 0xd8c76845c71a4482, 0xea03ea2ec2406c9b,
  0xe2498a52f95cd21e, 0xd4ffe046d9393212, 0x93565efec984c6c9,
  0x154c50d8c6e11dc9, 0x3cd889f3188c18cc, 0xb5a46a6cba1287ca,
  0xbc203b6c8f21bb66, 0xfedf97cba4c35dea, 0x0c82b3d9520de017,
  0xdb2674b14ddb4d95, 0x44c8e1ca851db784, 0x5596d3e27d211d55,
  0x9dbe804695d2270d, 0xbd54af74b050b82a, 0xe4ea34515f120cea,
  0xaa2564472972ab58, 0xf97af0d678dfd0cb, 0xdebdbc18d6c71bd1,
  0x78423e11438fcb21, 0xf6f749d4f30510d4, 0x68de10085ea4c2ea,
  0x6b3ff4773ccb4ec1, 0x33206eb82742f50e, 0x3046468ab04a0778,
  0xd7168cc59b78654c, 0xcb5800e03e2f90d9, 0x4f8fdaa4a3b0b5ff,
  0xe0eeff2c2ff94e64, 0x7f2578708dafae2e, 0x6feab0ef729b4300,
  0xf1de49e2796cfdf5, 0x90711a9f7886a0d0, 0xf4b39401ae61d28a,
  0x3f26008ddcbc47e9, 0xfab0a15c25a8511d, 0x2664fc987e7fdd17,
  0x51125228da560a04, 0x93a545c6207a3d67, 0x7c8e4446a408cc25,
  0xf9b10a00083f429e, 0x48704b0fc020d66c, 0x1e1a8c7a3d66eae0,
  0x9bde8e4692e41915, 0x7144aad3cf672129, 0xbab5e713e8f5b335,
  0x2d2c0b70c55d7d11, 0xed928a6e1b388ab0, 0xf121a4a71653448f,
  0x0dd175d00c20e9ed, 0xe68066507fb5dcb1, 0x92384f914830a50e,
  0xb4d4c84f220aed3d, 0xa13e4d6ea70cc5f0, 0xfdbe2223195bfa82,
  0xe97bb465c3ca2099, 0x0078ec86e8daa6c0, 0x634c3a1311b805c4,
  0xac04a89119ae79a7, 0x690e7049d8e8762f, 0x0000000000000086,
  0x0000000000000000,
};

#define perftest_aesXXX_var_sz(a)                                             \
  void __test_perf_fn perftest_aes##a##_var_sz (test_perf_t *tp)              \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_ctr_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    u8 *key = test_mem_alloc_and_fill_inc_u8 (32, 192, 0);                    \
    u8 *iv = test_mem_alloc_and_fill_inc_u8 (16, 128, 0);                     \
                                                                              \
    clib_aes_ctr_key_expand (kd, key, AES_KEY_##a);                           \
                                                                              \
    test_perf_event_enable (tp);                                              \
    clib_aes##a##_ctr (kd, src, n, iv, dst);                                  \
    test_perf_event_disable (tp);                                             \
  }

static clib_error_t *
test_clib_aes128_ctr (clib_error_t *err)
{
  aes_ctr_key_data_t kd;
  aes_ctr_ctx_t ctx;
  u8 pt[INC_TEST_BYTES];
  u8 ct[INC_TEST_BYTES];

  FOREACH_ARRAY_ELT (tc, test_cases128)
    {
      clib_aes_ctr_key_expand (&kd, tc->key, AES_KEY_128);
      clib_aes128_ctr (&kd, tc->pt, tc->data_len, tc->iv, ct);

      if (tc->data_len && memcmp (tc->ct, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  for (int i = 0; i < sizeof (pt); i++)
    pt[i] = i;

  clib_aes_ctr_key_expand (&kd, inc_key128, AES_KEY_128);
  clib_aes128_ctr (&kd, pt, INC_TEST_BYTES, inc_iv, ct);
  for (int i = 0; i < sizeof (pt); i++)
    if (((u8 *) inc_ct128)[i] != ct[i])
      return clib_error_return (err, "incremental test failed (byte %u)", i);

  clib_aes_ctr_init (&ctx, &kd, inc_iv, AES_KEY_128);
  for (u32 off = 0, chunk_size = 1; off < INC_TEST_BYTES;
       off += chunk_size, chunk_size = clib_min (((chunk_size + 1) * 2 - 1),
						 INC_TEST_BYTES - off))
    clib_aes_ctr_transform (&ctx, pt + off, ct + off, chunk_size, AES_KEY_128);

  for (int i = 0; i < sizeof (pt); i++)
    if (((u8 *) inc_ct128)[i] != ct[i])
      return clib_error_return (
	err, "incremental multiseg test failed (byte %u)", i);

  return err;
}

perftest_aesXXX_var_sz (128);
REGISTER_TEST (clib_aes128_ctr) = {
  .name = "clib_aes128_ctr",
  .fn = test_clib_aes128_ctr,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes128_var_sz }),
};

static clib_error_t *
test_clib_aes192_ctr (clib_error_t *err)
{
  aes_ctr_key_data_t kd;
  u8 ct[MAX_TEST_DATA_LEN];

  FOREACH_ARRAY_ELT (tc, test_cases192)
    {
      clib_aes_ctr_key_expand (&kd, tc->key, AES_KEY_192);
      clib_aes192_ctr (&kd, tc->pt, tc->data_len, tc->iv, ct);

      if (tc->data_len && memcmp (tc->ct, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  return err;
}

perftest_aesXXX_var_sz (192);
REGISTER_TEST (clib_aes192_ctr) = {
  .name = "clib_aes192_ctr",
  .fn = test_clib_aes192_ctr,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes192_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes192_var_sz }),
};

static clib_error_t *
test_clib_aes256_ctr (clib_error_t *err)
{
  aes_ctr_key_data_t kd;
  u8 ct[MAX_TEST_DATA_LEN];

  FOREACH_ARRAY_ELT (tc, test_cases256)
    {
      aes_ctr_ctx_t ctx;
      u32 sz = tc->data_len / 3;

      clib_aes_ctr_key_expand (&kd, tc->key, AES_KEY_256);
      clib_aes256_ctr (&kd, tc->pt, tc->data_len, tc->iv, ct);

      if (tc->data_len && memcmp (tc->ct, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
      clib_memset (ct, 0, tc->data_len);

      clib_aes_ctr_init (&ctx, &kd, tc->iv, AES_KEY_256);
      clib_aes_ctr_transform (&ctx, tc->pt, ct, sz, AES_KEY_256);
      clib_aes_ctr_transform (&ctx, tc->pt + sz, ct + sz, sz, AES_KEY_256);
      clib_aes_ctr_transform (&ctx, tc->pt + 2 * sz, ct + 2 * sz,
			      tc->data_len - 2 * sz, AES_KEY_256);
      if (tc->data_len && memcmp (tc->ct, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext (multiseg)",
				  tc->name);
    }

  return err;
}

perftest_aesXXX_var_sz (256);
REGISTER_TEST (clib_aes256_ctr) = {
  .name = "clib_aes256_ctr",
  .fn = test_clib_aes256_ctr,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes256_var_sz }),
};

#endif
