/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#if (defined(__AES__) && defined(__PCLMUL__)) || defined(__ARM_FEATURE_CRYPTO)
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crypto/aes_gcm.h>

static const u8 tc1_key128[16] = {
  0,
};

static const u8 tc1_iv[12] = {
  0,
};

static const u8 tc1_tag128[] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e,
				 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57,
				 0xa4, 0xe7, 0x45, 0x5a };
static const u8 tc1_key256[32] = {
  0,
};

static const u8 tc1_tag256[] = {
  0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
  0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
};

static const u8 tc2_ciphertext256[] = { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60,
					0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
					0xba, 0xf3, 0x9d, 0x18 };

static const u8 tc2_tag256[] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99,
				 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
				 0xd4, 0x8a, 0xb9, 0x19 };

static const u8 tc2_plaintext[16] = {
  0,
};

static const u8 tc2_tag128[] = { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec,
				 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2,
				 0x12, 0x57, 0xbd, 0xdf };

static const u8 tc2_ciphertext128[] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6,
					0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
					0x71, 0xb2, 0xfe, 0x78 };

static const u8 tc3_key128[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_iv[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
			     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };

static const u8 tc3_plaintext[] = {
  0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf,
  0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c,
  0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09,
  0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5,
  0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static const u8 tc3_ciphertext128[] = {
  0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84,
  0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1,
  0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93,
  0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39,
  0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};

static const u8 tc3_tag128[] = { 0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd,
				 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd,
				 0x2b, 0xa6, 0xfa, 0xb4 };

static const u8 tc3_key256[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73,
				 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
				 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86,
				 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_ciphertext256[] = {
  0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a,
  0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98,
  0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb,
  0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63,
  0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};

static const u8 tc3_tag256[] = { 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34,
				 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22,
				 0x70, 0xe3, 0xcc, 0x6c };

static const u8 tc4_plaintext[] = {
  0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
  0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
  0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
  0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
  0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
};

static const u8 tc4_aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			      0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
			      0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };

static const u8 tc4_ciphertext128[] = {
  0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
  0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
  0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
  0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
  0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
};

static const u8 tc4_tag128[] = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21,
				 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a,
				 0xe7, 0x12, 0x1a, 0x47 };

static const u8 tc4_ciphertext256[] = {
  0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
  0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
  0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
  0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
  0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62
};

static const u8 tc4_tag256[] = { 0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e,
				 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53,
				 0xbb, 0x2d, 0x55, 0x1b };

static const u8 inc_key[] = { 0x97, 0x3e, 0x43, 0x70, 0x84, 0x71, 0xd4, 0xe2,
			      0x45, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x5f, 0x3b,
			      0x97, 0x3e, 0x43, 0x70, 0x84, 0x71, 0xd4, 0xe2,
			      0x45, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x5f, 0x3b };
static const u8 inc_iv[] = { 0xe2, 0xe4, 0x3f, 0x29, 0xfe, 0xd4,
			     0xbc, 0x31, 0x56, 0xa7, 0x97, 0xf5 };

static const struct
{
  const u16 n_bytes;
  const u64 tag_gcm_128[2];
  const u64 tag_gcm_256[2];
  const u64 tag_gmac_128[2];
  const u64 tag_gmac_256[2];
  const u8 tag256[16];
} inc_test_cases[] = {
  {
    .n_bytes = 0,
    .tag_gcm_128 = { 0x95f4b8cc824294eb, 0xbf964ccf94b47f96 },
    .tag_gcm_256 = { 0x206b456eaa81a3c8, 0xa308160d180e080d },
    .tag_gmac_128 = { 0x95f4b8cc824294eb, 0xbf964ccf94b47f96 },
    .tag_gmac_256 = { 0x206b456eaa81a3c8, 0xa308160d180e080d },
  },
  {
    .n_bytes = 1,
    .tag_gcm_128 = { 0xe89aa5be94fa1db4, 0x70d82ed02542a560 },
    .tag_gcm_256 = { 0xcb0659b38e60d3a7, 0x9758b874959187ff },
    .tag_gmac_128 = { 0xf9be1e7db073c565, 0x3b8a0ecc7a91f09d },
    .tag_gmac_256 = { 0x1e302e97ab394130, 0xef29621c33bdb710 },
  },
  {
    .n_bytes = 7,
    .tag_gcm_128 = { 0xf4af7cbe57bd2078, 0x063dd60abbe51049 },
    .tag_gcm_256 = { 0x7d231388fe8a19be, 0x59be3e7205269abd },
    .tag_gmac_128 = { 0x27d0a47980eed1c6, 0xe6163485e73d02b3 },
    .tag_gmac_256 = { 0x61ce281b47729f6c, 0x128a6bc0880e5d84 },
  },
  {
    .n_bytes = 8,
    .tag_gcm_128 = { 0xf45b40961422abc4, 0x0a932b98c4999694 },
    .tag_gcm_256 = { 0xf7f945beed586ee2, 0x67239433a7bd3f23 },
    .tag_gmac_128 = { 0x3a25d38572abe3b1, 0x220798aca96d594a },
    .tag_gmac_256 = { 0x2e0e6d58d1ab41ca, 0x09bbc83e3b7b5e11 },
  },
  {
    .n_bytes = 9,
    .tag_gcm_128 = { 0x791b0a879d236364, 0xde9553e3ed1b763f },
    .tag_gcm_256 = { 0x24c13ed7b46813cd, 0xe646ce24ea4b281e },
    .tag_gmac_128 = { 0x0e521672b23a4fc7, 0x16f129224dec5fd8 },
    .tag_gmac_256 = { 0x8b9c603789c34043, 0x0a8b626928c9fb6f },
  },
  {
    .n_bytes = 15,
    .tag_gcm_128 = { 0xb277ef05e2be1cc0, 0x2922fba5e321c81e },
    .tag_gcm_256 = { 0xc3ca9f633fa803dc, 0x96e60b0c3347d744 },
    .tag_gmac_128 = { 0xab99e6327c8e1493, 0x09a9a153045ba43f },
    .tag_gmac_256 = { 0xfc9ec2d6a1ad492b, 0xf0b0ba877663732d },
  },
  {
    .n_bytes = 16,
    .tag_gcm_128 = { 0x3e3438e8f932ebe3, 0x958e270d56ae588e },
    .tag_gcm_256 = { 0x6ac53524effc8171, 0xccab3a16a0b5813c },
    .tag_gmac_128 = { 0x0eb4a09c6c7db16b, 0x1cdb5573a27a2e4a },
    .tag_gmac_256 = { 0x71752018b31eae33, 0xdc4bd36d44b9fd5d },
  },
  {
    .n_bytes = 31,
    .tag_gcm_128 = { 0x1f4d4a7a056e4bca, 0x97ac76121dccb4e0 },
    .tag_gcm_256 = { 0x609aea9aec919ab6, 0x1eba3c4998e7abb9 },
    .tag_gmac_128 = { 0x289280f9e8879c68, 0xe6b0e36afc0d2ae1 },
    .tag_gmac_256 = { 0x0b3f61762ba4ed43, 0x293f596a76d63b37 },
  },
  {
    .n_bytes = 32,
    .tag_gcm_128 = { 0xc4b64505d045818f, 0x72bfd499f0f983b4 },
    .tag_gcm_256 = { 0x3f003fb179b2c480, 0x883876d4904700c2 },
    .tag_gmac_128 = { 0x3dd10ab954d807f0, 0x5ae32ee41675051e },
    .tag_gmac_256 = { 0x1a80ab830fc736c0, 0x51db27630adae337 },
  },
  {
    .n_bytes = 47,
    .tag_gcm_128 = { 0x3aedb0c6c14f2ea1, 0xe4626626bae641cd },
    .tag_gcm_256 = { 0x9c91b87dfd302880, 0x05bb594dde5abb9c },
    .tag_gmac_128 = { 0xe0fe54f2bdadeba8, 0x6f8f40edb569701f },
    .tag_gmac_256 = { 0x26c5632c7abbdb3f, 0xc18ccc24df8bb239 },
  },
  {
    .n_bytes = 48,
    .tag_gcm_128 = { 0xdbceb2aed0dbbe27, 0xfef0013e8ebe6ef1 },
    .tag_gcm_256 = { 0x98ad025f30b58ffa, 0xabc8a99857034e42 },
    .tag_gmac_128 = { 0x269518e8584b7f6c, 0x1c9f41410a81799c },
    .tag_gmac_256 = { 0x144807ce7aa8eb61, 0x611a8355b4377dc6 },
  },
  {
    .n_bytes = 63,
    .tag_gcm_128 = { 0x1769ccf523a2046e, 0x7328e18749a559b4 },
    .tag_gcm_256 = { 0xcdf2f28efa9689ce, 0x636676f6aedea9de },
    .tag_gmac_128 = { 0x4d47537060defce8, 0x0d4819c20ba8e889 },
    .tag_gmac_256 = { 0x7b60615e7bfc9a7a, 0x610633296eb30b94 },
  },
  {
    .n_bytes = 64,
    .tag_gcm_128 = { 0xa5602f73865b6a77, 0x78317e461ff9b560 },
    .tag_gcm_256 = { 0x5c17a6dcd1f23b65, 0x25331c378256a93e },
    .tag_gmac_128 = { 0x39d941ed85d81ab0, 0xe358a61078628d63 },
    .tag_gmac_256 = { 0x5276fbdd333f380d, 0xb0dc63e68f137e74 },
  },
  {
    .n_bytes = 79,
    .tag_gcm_128 = { 0x5d32cd75f2e82d84, 0xbc15801c1fe285bd },
    .tag_gcm_256 = { 0xb2b2855f4b1ecf70, 0xa524adc1609c757b },
    .tag_gmac_128 = { 0xa147493f08a8738e, 0xbf07da9f4a88944f },
    .tag_gmac_256 = { 0xfee15e0d4b936bc7, 0x1dc88398c6b168bc },
  },
  {
    .n_bytes = 80,
    .tag_gcm_128 = { 0xa303b7247b9b00df, 0xe72d6d7063d48b72 },
    .tag_gcm_256 = { 0x7abfffc9ecfa00ec, 0x9c5ffcd753ee4568 },
    .tag_gmac_128 = { 0xc3e61bf9f370b40e, 0x66b1c4a6df3b19d7 },
    .tag_gmac_256 = { 0x0cc7b09a7d602352, 0x29e8a64447a764d2 },
  },
  {
    .n_bytes = 95,
    .tag_gcm_128 = { 0xf0fb35c36eac3025, 0xa13463307fc48907 },
    .tag_gcm_256 = { 0x283a73a05bd0e3c2, 0x794a181dd07a0fb7 },
    .tag_gmac_128 = { 0x26f3546060d9f958, 0xc1367fca8869ab40 },
    .tag_gmac_256 = { 0xa046e1705100c711, 0xbcf9d6a06f360260 },
  },
  {
    .n_bytes = 96,
    .tag_gcm_128 = { 0x974bb3c1c258bfb5, 0xcf057344bccb0596 },
    .tag_gcm_256 = { 0x18920d75fcfb702e, 0x18e5f14ba429b7be },
    .tag_gmac_128 = { 0xf43cca4837ad00b8, 0xb1a1585d51838352 },
    .tag_gmac_256 = { 0xce3427dc5123b31f, 0xdcc6e49fa0f6587e },
  },
  {
    .n_bytes = 111,
    .tag_gcm_128 = { 0x5d73baa8eef0ced3, 0x79339e31d5d813de },
    .tag_gcm_256 = { 0x4cefa311c9c39a86, 0xe809ee78930ef736 },
    .tag_gmac_128 = { 0x452003e6d535a523, 0x723f08581012c62e },
    .tag_gmac_256 = { 0x6ce2e1661db942ca, 0xccd700c9c6d03cfd },
  },
  {
    .n_bytes = 112,
    .tag_gcm_128 = { 0x189aa61ce15a0d11, 0xc907e6bccbdbb8f9 },
    .tag_gcm_256 = { 0xa41c96c843b791b4, 0x0f9f60953f03e5fc },
    .tag_gmac_128 = { 0x44c75b94dbf8539f, 0xcdebe3ed9c68c840 },
    .tag_gmac_256 = { 0x21a289dd39eadd19, 0x749a038e1ea0711c },
  },
  {
    .n_bytes = 127,
    .tag_gcm_128 = { 0xc6ea87bfe82d73f6, 0x9d85dbf8072bb051 },
    .tag_gcm_256 = { 0xd5e436b2ddfac9fa, 0x54d7d13fa214703a },
    .tag_gmac_128 = { 0xdc5374b7d7d221c4, 0xa8cf4e11958b9dff },
    .tag_gmac_256 = { 0xc7ad0bba9de54f6a, 0x38ed037fe0924dee },
  },
  {
    .n_bytes = 128,
    .tag_gcm_128 = { 0x357d4954b7c2b440, 0xb3b07ce0cd143149 },
    .tag_gcm_256 = { 0x5555d09cb247322d, 0xeb9d1cea38b68951 },
    .tag_gmac_128 = { 0x6a77579181663dde, 0xe359157bd4246d3f },
    .tag_gmac_256 = { 0x9fe930d50d661e37, 0xba4a0f3c3a6b63cf },
  },
  {
    .n_bytes = 143,
    .tag_gcm_128 = { 0x358f897d4783966f, 0x6fa44993a9ed54c4 },
    .tag_gcm_256 = { 0x60e91f959f2ccdbe, 0x116c56fdaa107deb },
    .tag_gmac_128 = { 0x121d26aba8aaee0d, 0xc37cda9c43f51008 },
    .tag_gmac_256 = { 0x06918b1cd20e0abc, 0x42938b1d8e745dcd },
  },
  {
    .n_bytes = 144,
    .tag_gcm_128 = { 0x8a9efe3df387e069, 0xc0a3f2f7547c704b },
    .tag_gcm_256 = { 0x217d59f53bfbc314, 0x2d8f088d05532b0d },
    .tag_gmac_128 = { 0x382949d56e0e8f05, 0x4e87fb8f83f095a7 },
    .tag_gmac_256 = { 0x75e07060883db37d, 0x5fde7b9bda37d680 },
  },
  {
    .n_bytes = 159,
    .tag_gcm_128 = { 0x297252081cc8db1e, 0x6357143fa7f756c8 },
    .tag_gcm_256 = { 0x7e8fca9d1b17e003, 0x7bf7dad063b9a5c9 },
    .tag_gmac_128 = { 0x5d0524b130e97547, 0xd6befd8591072437 },
    .tag_gmac_256 = { 0xf5f631d391b635fc, 0xe8f7b6808544f312 },
  },
  {
    .n_bytes = 160,
    .tag_gcm_128 = { 0x90e034ee0f08a871, 0x002f483eefa24ec9 },
    .tag_gcm_256 = { 0xed24df02e455d6d3, 0x7a7d318ed132cb7f },
    .tag_gmac_128 = { 0xc75f87215ae12a2f, 0xf264e5381d5b0412 },
    .tag_gmac_256 = { 0x1ad3e294fd55b0a6, 0xa1a551e59fd12e2f },
  },
  {
    .n_bytes = 175,
    .tag_gcm_128 = { 0x8f663955c8e4249e, 0xd9d8d8d7352b18d9 },
    .tag_gcm_256 = { 0xd9af34eae74a35e1, 0xc22e74b34267e5df },
    .tag_gmac_128 = { 0xb54a2e8b186a55db, 0x980f586c6da8afce },
    .tag_gmac_256 = { 0x9cceb31baad18ff1, 0xce97588909ece8af },
  },
  {
    .n_bytes = 176,
    .tag_gcm_128 = { 0x258ec0df82f003bd, 0x571496e92c966695 },
    .tag_gcm_256 = { 0xa1925cda1fa1dd2c, 0x914038618faecf99 },
    .tag_gmac_128 = { 0xfc384b412bdb05ef, 0x73968cf3b464a997 },
    .tag_gmac_256 = { 0x50d9ce4be242e176, 0x5fb78e9404c9226d },
  },
  {
    .n_bytes = 191,
    .tag_gcm_128 = { 0x796a90a3edaab614, 0x4bf34c2c6333c736 },
    .tag_gcm_256 = { 0x4ffd3a84b346c6d5, 0x9d4c84c7ac5a191c },
    .tag_gmac_128 = { 0x16c11c6bfad5973e, 0xa0825b9c827137c8 },
    .tag_gmac_256 = { 0x82c144c209c22758, 0x7428b4ac38a65c56 },
  },
  {
    .n_bytes = 192,
    .tag_gcm_128 = { 0x2a44492af2e06a75, 0xbe4eab62aacfc2d3 },
    .tag_gcm_256 = { 0xb7d4971a8061092d, 0x94da543669369e41 },
    .tag_gmac_128 = { 0xed462726c984b596, 0xd61b317d979f5df8 },
    .tag_gmac_256 = { 0x554dc7f30981dbf6, 0x94447d0fbf9f2c8b },
  },
  {
    .n_bytes = 207,
    .tag_gcm_128 = { 0xcfac9f67252713c8, 0xd638cf6b74c6acf6 },
    .tag_gcm_256 = { 0x57a4a9d299663925, 0xa802f8453e8bcc5b },
    .tag_gmac_128 = { 0xef03f3cdcb0ea819, 0xeea8f0f7f805c306 },
    .tag_gmac_256 = { 0x3d8cd7d92cf0a212, 0x12c1ddddab7e752c },
  },
  {
    .n_bytes = 208,
    .tag_gcm_128 = { 0x5467633795b92cf5, 0x6b45fb93e19f9341 },
    .tag_gcm_256 = { 0xaeced4090d4d20bc, 0xd20161cd2617613e },
    .tag_gmac_128 = { 0x02bb88dbe681ab69, 0xaf973bfd0b924144 },
    .tag_gmac_256 = { 0x313020fc5283b45e, 0x1757616d4cf17c7f },
  },
  {
    .n_bytes = 223,
    .tag_gcm_128 = { 0x2f9c725903c07adf, 0xe01712c7d6d5055d },
    .tag_gcm_256 = { 0xeae53a9b0d03a4f9, 0x42b2375d569d384e },
    .tag_gmac_128 = { 0x6ea092dd400ec00d, 0x23237fa0bd0c1977 },
    .tag_gmac_256 = { 0xa02e0f41f12f0053, 0xfba53430aa616219 },
  },
  {
    .n_bytes = 224,
    .tag_gcm_128 = { 0x73e40772334901a9, 0xddf6075b357cb307 },
    .tag_gcm_256 = { 0x2eb3450f9462c968, 0xa9fb95f281c117e9 },
    .tag_gmac_128 = { 0x33762525c12dfd1d, 0xcb3d8d0402c23ebf },
    .tag_gmac_256 = { 0x30c6d05fb98c2a84, 0xaa2c9f6303383d3a },
  },
  {
    .n_bytes = 239,
    .tag_gcm_128 = { 0x184d15fd2e2c63a6, 0x3dfe238b88dd2924 },
    .tag_gcm_256 = { 0x18deafee39975b36, 0xc07761cf4fc16c06 },
    .tag_gmac_128 = { 0x10a48f2bc4e64f87, 0x85eec49ae83d4256 },
    .tag_gmac_256 = { 0x5ac87f47f32770eb, 0x31706ca888dd6d44 },
  },
  {
    .n_bytes = 240,
    .tag_gcm_128 = { 0x153134f11cfa06ec, 0xd987642cc3688a34 },
    .tag_gcm_256 = { 0x3eb66b6dc0bba824, 0x274c4648d515c844 },
    .tag_gmac_128 = { 0x9e5afe891c7c7dcb, 0xa2b3fa1c026343e2 },
    .tag_gmac_256 = { 0xe9120e4e9ff4b1e1, 0xb88bf68336342598 },
  },
  {
    .n_bytes = 255,
    .tag_gcm_128 = { 0x2b5e78936d1ace73, 0x15b766bfee18d348 },
    .tag_gcm_256 = { 0xeb3741a345395c97, 0x02e11e0478e4cc5a },
    .tag_gmac_128 = { 0xf7daf525751192df, 0x1b1641c3362905ac },
    .tag_gmac_256 = { 0x0b16a2bb842caaca, 0x996732fedaa6b829 },
  },
  {
    .n_bytes = 256,
    .tag_gcm_128 = { 0x6d4507e0c354e80a, 0x2345eccddd0bd71e },
    .tag_gcm_256 = { 0xa582b8122d699b63, 0xb16db944f6b073f3 },
    .tag_gmac_128 = { 0xc58bb57544c07b40, 0x1a8dd3d8124cdf39 },
    .tag_gmac_256 = { 0xb0f6db0da52e1dc2, 0xbd3a86a577ed208a },
  },
  {
    .n_bytes = 319,
    .tag_gcm_128 = { 0x2cd41fdf6f659a6b, 0x2486849d7666d76e },
    .tag_gcm_256 = { 0xb7e416c8a716cb4d, 0xc7abe0d755b48845 },
    .tag_gmac_128 = { 0xad83725394d4a36b, 0x5fdd42e941cad49b },
    .tag_gmac_256 = { 0xbb0b73609b90f7eb, 0xe4d382b8b9b7d43e },
  },
  {
    .n_bytes = 320,
    .tag_gcm_128 = { 0x064cfe34b7d9f89c, 0xb6c7263f66c89b47 },
    .tag_gcm_256 = { 0x1254c9ae84d8ff50, 0x9faeab423099dc9a },
    .tag_gmac_128 = { 0xd91d60ce71d24533, 0xb1cdfd3b3200b171 },
    .tag_gmac_256 = { 0x921de9e3d353559c, 0x3509d2775817a1de },
  },
  {
    .n_bytes = 383,
    .tag_gcm_128 = { 0x14788c7531d682e1, 0x8af79effe807a4dc },
    .tag_gcm_256 = { 0x947754a0844b4a4d, 0x9eb3849d93d5048e },
    .tag_gmac_128 = { 0xfa84d3a18ea6f895, 0x9a45c729797a8ac4 },
    .tag_gmac_256 = { 0xe8e61e134e40359a, 0xe8e404d4b523607c },
  },
  {
    .n_bytes = 384,
    .tag_gcm_128 = { 0xfba3fcfd9022e9a7, 0x257ba59f12055d70 },
    .tag_gcm_256 = { 0x7c6ca4e7fba2bc35, 0x1c590be09b3d549b },
    .tag_gmac_128 = { 0x4ca0f087d812e48f, 0xd1d39c4338d57a04 },
    .tag_gmac_256 = { 0xb0a2257cdec364c7, 0x6a4308976fda4e5d },
  },
  {
    .n_bytes = 447,
    .tag_gcm_128 = { 0x8fde1490c60f09bf, 0xd2932f04c202c5e4 },
    .tag_gcm_256 = { 0x1845a80cbdcf2e62, 0xc7c49c9864bca732 },
    .tag_gmac_128 = { 0x35aa90d2deb41b9c, 0x516ab85a3f17b71e },
    .tag_gmac_256 = { 0x1db78f8b7b34d9e7, 0xd168177351e601fe },
  },
  {
    .n_bytes = 448,
    .tag_gcm_128 = { 0xd0a7b75f734a1a7c, 0xc7689b7c571a09bf },
    .tag_gcm_256 = { 0xef3a9118c347118d, 0x282a7736060d7bb5 },
    .tag_gmac_128 = { 0xce2dab9fede53934, 0x27f3d2bb2af9dd2e },
    .tag_gmac_256 = { 0xca3b0cba7b772549, 0x3104ded0d6df7123 },
  },
  {
    .n_bytes = 511,
    .tag_gcm_128 = { 0x6fb5d366fa97b2d2, 0xed2d955fcc78e556 },
    .tag_gcm_256 = { 0xc2bc52eca9348b7c, 0x0ec18a2eb637446f },
    .tag_gmac_128 = { 0xe3012a4897edd5b5, 0xfe18c3ec617a7e88 },
    .tag_gmac_256 = { 0x00e050eecf184591, 0xba24484f84867f4f },
  },
  {
    .n_bytes = 512,
    .tag_gcm_128 = { 0x25138f7fe88b54bd, 0xcc078b619c0e83a2 },
    .tag_gcm_256 = { 0x63313c5ebe68fa92, 0xccc78784896cdcc3 },
    .tag_gmac_128 = { 0xc688fe54c5595ec0, 0x5b8a687343c3ef03 },
    .tag_gmac_256 = { 0x807c9f8e1c198242, 0xb1e0befc0b9b8193 },
  },
  {
    .n_bytes = 575,
    .tag_gcm_128 = { 0x0ce8e0b7332a7076, 0xe4aa7ab60dd0946a },
    .tag_gcm_256 = { 0x585cff3cf78504d4, 0x45f3a9532ea40e8b },
    .tag_gmac_128 = { 0xc06ca34dbad542b4, 0x840508722ff031dc },
    .tag_gmac_256 = { 0xa46e22748f195488, 0x43817a5d4d17408a },
  },
  {
    .n_bytes = 576,
    .tag_gcm_128 = { 0x45360be81e8323bd, 0x10892d9804b75bb5 },
    .tag_gcm_256 = { 0x66208ae5d809036e, 0x603d0af49475de88 },
    .tag_gmac_128 = { 0xb4f2b1d05fd3a4ec, 0x6a15b7a05c3a5436 },
    .tag_gmac_256 = { 0x8d78b8f7c7daf6ff, 0x925b2a92acb7356a },
  },
  {
    .n_bytes = 577,
    .tag_gcm_128 = { 0xc7e5cd17251fd138, 0xecfb0e05110303df },
    .tag_gcm_256 = { 0x2939d12c85ea8cf8, 0xea063fba37c92eb5 },
    .tag_gmac_128 = { 0x1fa02b370bec64a0, 0x8c759ca95a8cea85 },
    .tag_gmac_256 = { 0x6a602c2b1fff6617, 0x17e06d829bd24a8d },
  },
  {
    .n_bytes = 639,
    .tag_gcm_128 = { 0xc679ef7a01e8f14c, 0x281e3b9a9f715cb9 },
    .tag_gcm_256 = { 0x13abd2d67e162f98, 0xf637d467046af949 },
    .tag_gmac_128 = { 0x05037392550b7ae2, 0x5095b4629ba46d40 },
    .tag_gmac_256 = { 0xd8e8045772299aa7, 0x564d72fb58ea9808 },
  },
  {
    .n_bytes = 640,
    .tag_gcm_128 = { 0xff1a2c922cdd1336, 0xcaa02eab8691bf51 },
    .tag_gcm_256 = { 0xd57e16f169d79da5, 0x3e2b47264f8efe9c },
    .tag_gmac_128 = { 0xb32750b403bf66f8, 0x1b03ef08da0b9d80 },
    .tag_gmac_256 = { 0x80ac3f38e2aacbfa, 0xd4ea7eb88213b629 },
  },
  {
    .n_bytes = 703,
    .tag_gcm_128 = { 0xefd0804f0155b8f1, 0xb1849ed867269569 },
    .tag_gcm_256 = { 0xf66c5ecbd1a06fa4, 0x55ef36f3fdbe763a },
    .tag_gmac_128 = { 0x725813463d977e5b, 0xd52aaabb923cfabb },
    .tag_gmac_256 = { 0x4add8f86736adc52, 0xf6dabb4596975fd7 },
  },
  {
    .n_bytes = 704,
    .tag_gcm_128 = { 0x583b29260ea8e49f, 0xfaa93b0db98f9274 },
    .tag_gcm_256 = { 0x0b777f2cd9e2f0ef, 0x01510fc85a99382e },
    .tag_gmac_128 = { 0x89df280b0ec65cf3, 0xa3b3c05a87d2908b },
    .tag_gmac_256 = { 0x9d510cb7732920fc, 0x16b672e611ae2f0a },
  },
  {
    .n_bytes = 767,
    .tag_gcm_128 = { 0x671ec58ab6d4a210, 0x0845fbe603169eff },
    .tag_gcm_256 = { 0xb3913f7eb9bbdbbb, 0x4cb17aa290f6ab11 },
    .tag_gmac_128 = { 0x3036046580a81443, 0xe18d34bb706e632b },
    .tag_gmac_256 = { 0x4e82bc959349466c, 0x01210641d62bbdda },
  },
  {
    .n_bytes = 768,
    .tag_gcm_128 = { 0x66993b5de915fc6e, 0x4aaf0b8441040267 },
    .tag_gcm_256 = { 0x958ed0a6c1bf11e0, 0xc29d9f4a8ce8bdc6 },
    .tag_gmac_128 = { 0x02674435b179fddc, 0xe016a6a0540bb9be },
    .tag_gmac_256 = { 0xf562c523b24bf164, 0x257cb21a7b602579 },
  },
  {
    .n_bytes = 831,
    .tag_gcm_128 = { 0x4914f7980699f93c, 0xc2e44fdba6a839e7 },
    .tag_gcm_256 = { 0xa8fab43ecd572a25, 0x3cd465e491195b81 },
    .tag_gmac_128 = { 0xa6d725516e956d5d, 0x630768e80ac3de3d },
    .tag_gmac_256 = { 0xb4746cdde367c9e2, 0x3ea53280901a0375 },
  },
  {
    .n_bytes = 832,
    .tag_gcm_128 = { 0xac9a519f06fb8c70, 0xdc1a6544ed2cfcf7 },
    .tag_gcm_256 = { 0x54877a7ccd02c592, 0x1a09a4474d903b56 },
    .tag_gmac_128 = { 0xd24937cc8b938b05, 0x8d17d73a7909bbd7 },
    .tag_gmac_256 = { 0x9d62f65eaba46b95, 0xef7f624f71ba7695 },
  },
  {
    .n_bytes = 895,
    .tag_gcm_128 = { 0x3d365bf4d44c1071, 0x07ac3129079f2013 },
    .tag_gcm_256 = { 0x608543d4fe6526a1, 0xc78a987b87c8d96c },
    .tag_gmac_128 = { 0xc71cf903f7a557c5, 0x06788583ad2122a5 },
    .tag_gmac_256 = { 0x7cdaa511565b289a, 0xf818a4c85a8bd575 },
  },
  {
    .n_bytes = 896,
    .tag_gcm_128 = { 0x97000fafd1359a0b, 0xfc226d534866b495 },
    .tag_gcm_256 = { 0x1850ee7af3133326, 0xf198d539eee4b1f5 },
    .tag_gmac_128 = { 0x7138da25a1114bdf, 0x4deedee9ec8ed265 },
    .tag_gmac_256 = { 0x249e9e7ec6d879c7, 0x7abfa88b8072fb54 },
  },
  {
    .n_bytes = 959,
    .tag_gcm_128 = { 0x17200025564902f2, 0x3f2c3b711ba4086d },
    .tag_gcm_256 = { 0x3d0bf3e8b24e296d, 0x42fe0f54e33deb6d },
    .tag_gmac_128 = { 0x8baae9b6f3bd797a, 0x177e0b6c577f2436 },
    .tag_gmac_256 = { 0x853f961c965f472c, 0x8adc4113b3cf933a },
  },
  {
    .n_bytes = 960,
    .tag_gcm_128 = { 0x2a30ca7325e7a81b, 0xacbc71832bdceb63 },
    .tag_gcm_256 = { 0x037786319dc22ed7, 0x6730acf359ec3b6e },
    .tag_gmac_128 = { 0x702dd2fbc0ec5bd2, 0x61e7618d42914e06 },
    .tag_gmac_256 = { 0x52b3152d961cbb82, 0x6ab088b034f6e3e7 },
  },
  {
    .n_bytes = 1023,
    .tag_gcm_128 = { 0x8e8789e6c4c90855, 0x4ec5503d7f953df6 },
    .tag_gcm_256 = { 0xdb0afebe6c085f53, 0x4eb6f07b63b8a020 },
    .tag_gmac_128 = { 0x6e9b48e5ad508180, 0xdc86430db2bad514 },
    .tag_gmac_256 = { 0xbb52b4fbf236b741, 0x47ae63bc836dfba3 },
  },
  {
    .n_bytes = 1024,
    .tag_gcm_128 = { 0x94e1ccbea0f24089, 0xf51b53b600363bd2 },
    .tag_gcm_256 = { 0x70f3eb3d562f0b34, 0xffd09e1a25d5bef3 },
    .tag_gmac_128 = { 0x65a2b560392ecee3, 0x30079a9a9dbbd3a3 },
    .tag_gmac_256 = { 0x4d361736c43090e6, 0x135810df49dcc981 },
  },
  {
    .n_bytes = 1025,
    .tag_gcm_128 = { 0x830a99737df5a71a, 0xd9ea6e87c63d3aae },
    .tag_gcm_256 = { 0xa3fc30e0254a5ee2, 0x52e59adc9a75be40 },
    .tag_gmac_128 = { 0xb217556427fc09ab, 0xc32fd72ec886730d },
    .tag_gmac_256 = { 0xeab5a9a02cb0869e, 0xd59e51684bc2839c },
  },
  {
    .n_bytes = 1039,
    .tag_gcm_128 = { 0x238f229130e92934, 0x52752fc860bca067 },
    .tag_gcm_256 = { 0xae2754bcaed68191, 0xe0770d1e9a7a67f3 },
    .tag_gmac_128 = { 0xe030ad2beb01d85d, 0xf10c78b1b64c27af },
    .tag_gmac_256 = { 0x081b45e126248e85, 0xca0789f30e1c47a1 },
  },
  {
    .n_bytes = 1040,
    .tag_gcm_128 = { 0x4eebcf7391d66c6f, 0x107d8bef4a93d9c6 },
    .tag_gcm_256 = { 0xbeb02ae5466964f3, 0x8eb90364c5f9e4cb },
    .tag_gmac_128 = { 0x451deb85fbf27da5, 0xe47e8c91106dadda },
    .tag_gmac_256 = { 0x85f0a72f3497699d, 0xe6fce0193cc6c9d1 },
  },
  {
    .n_bytes = 1041,
    .tag_gcm_128 = { 0xbbddfb0304411d71, 0xe573f63553d7ede4 },
    .tag_gcm_256 = { 0x68e42d2959af0b24, 0x35ac8e73c749e7f4 },
    .tag_gmac_128 = { 0x98d022b9896b68f8, 0x98dfde2a17b2869b },
    .tag_gmac_256 = { 0xb8dac6add35d0d9b, 0x1c55973c6dd769af },
  },
  {
    .n_bytes = 1536,
    .tag_gcm_128 = { 0x7d8933fd922418bd, 0xc88c2f289c5d3d83 },
    .tag_gcm_256 = { 0x966c103eb6ee69f2, 0x2f6b070b5c0fc66f },
    .tag_gmac_128 = { 0x3b70f6154246e758, 0xd485c0edf236b6e2 },
    .tag_gmac_256 = { 0xfefe1832387b9768, 0xc876712098256ca3 },
  },
  {
    .n_bytes = 2047,
    .tag_gcm_128 = { 0x15c6bbcb0d835fd4, 0xc33afd1328c1deb1 },
    .tag_gcm_256 = { 0xcde3edeea228ada6, 0x8276721a8662e708 },
    .tag_gmac_128 = { 0xb556b0e42419759e, 0x23b0365cf956a3ad },
    .tag_gmac_256 = { 0x8df762cbbe4b2a04, 0x6841bc61e5702419 },
  },
  {
    .n_bytes = 2048,
    .tag_gcm_128 = { 0xc5ddbeb8765e3aac, 0x1bad7349fd9f2b50 },
    .tag_gcm_256 = { 0xa2a623dde251a98d, 0xaf905fbd16f6a7d9 },
    .tag_gmac_128 = { 0xe20f1e533df2b3d0, 0x5d170bdbcc278a63 },
    .tag_gmac_256 = { 0x9663185c4342cd4a, 0x82d3c5a3a4998fc6 },
  },
  {
    .n_bytes = 2064,
    .tag_gcm_128 = { 0x12b76ea0a6ee9cbc, 0xdaecfae7c815aa58 },
    .tag_gcm_256 = { 0xb5bb2f76028713dd, 0xc8f3a1448b3bd050 },
    .tag_gmac_128 = { 0x019445c168c42f9b, 0xdf33e251bd9a27fe },
    .tag_gmac_256 = { 0xbbabd0cefc4d6a42, 0xb138675ca66ba54f },
  },
  {
    .n_bytes = 2065,
    .tag_gcm_128 = { 0x8758c5168ffc3fd7, 0x554f1df7cfa3b976 },
    .tag_gcm_256 = { 0xc9808cf0fd21aede, 0xe26921f3fd308006 },
    .tag_gmac_128 = { 0x44a57e7a32031596, 0x75476d5542faa57b },
    .tag_gmac_256 = { 0xea0e81807fa79a4a, 0x889cca80746fb8d5 },
  },
  {
    .n_bytes = 4095,
    .tag_gcm_128 = { 0x06db87757f541dc9, 0x823c619c6b88ef80 },
    .tag_gcm_256 = { 0xdf0861a56a7fe7b0, 0xe077a5c735cc21b2 },
    .tag_gmac_128 = { 0x43cb482bea0449e9, 0x70d668af983c9a6c },
    .tag_gmac_256 = { 0x5fc304ad7be1d19a, 0x81bf2f4111de0b06 },
  },
  {
    .n_bytes = 4096,
    .tag_gcm_128 = { 0xe4afdad642876152, 0xf78cfcfcb92520b6 },
    .tag_gcm_256 = { 0x7552cda8d91bdab1, 0x4bf57b7567d59e89 },
    .tag_gmac_128 = { 0xac5240f8e9c49cfc, 0x2a3c9d0999aded50 },
    .tag_gmac_256 = { 0x9fb6cd8f10f7b6c5, 0x16e442c147869222 },
  },
  {
    .n_bytes = 4112,
    .tag_gcm_128 = { 0x2a34db8f06bcf0ee, 0x7a4a2456fa340c33 },
    .tag_gcm_256 = { 0x4b6c0c5b5c943f5e, 0x6d1669e849ce061a },
    .tag_gmac_128 = { 0x143bfc9ab07d9bb5, 0xf0aa7510a9039349 },
    .tag_gmac_256 = { 0x8a97bdd033775ba0, 0x5901a5160739be25 },
  },
  {
    .n_bytes = 4113,
    .tag_gcm_128 = { 0x296acfcbcbf529af, 0xe3e2cfb1bc5855c8 },
    .tag_gcm_256 = { 0x181f6f9068ea477e, 0x1e05bfd01ee3e173 },
    .tag_gmac_128 = { 0x0d81fcb0829e3c8b, 0x68016225b5fa7745 },
    .tag_gmac_256 = { 0xa2421ac50d65c6b5, 0x84bd16fa55486af8 },
  },
  {
    .n_bytes = 16382,
    .tag_gcm_128 = { 0xd39fd367e00a103d, 0xf873a278b32d207f },
    .tag_gcm_256 = { 0xa8da09a851ae6c88, 0x2ef17f0da7f191f1 },
    .tag_gmac_128 = { 0xd4a22896f44c1c14, 0x69a5d02715c90ea4 },
    .tag_gmac_256 = { 0x64788ca5e11722b6, 0x63d74a4b24538762 },
  },
  {
    .n_bytes = 16383,
    .tag_gcm_128 = { 0x2162b91aad49eebc, 0x28c7efe93e639c75 },
    .tag_gcm_256 = { 0xc5baee5e40004087, 0xf6b26211facc66a5 },
    .tag_gmac_128 = { 0x3ec003d690d3d846, 0x204baef851d8ad7d },
    .tag_gmac_256 = { 0xdb51d6f5dddf16bb, 0x529f3825cf78dbd5 },
  },
  {
    .n_bytes = 16384,
    .tag_gcm_128 = { 0x2272e778c4c5c9ef, 0x84c50021e75ddbab },
    .tag_gcm_256 = { 0x6c32f1c5666b1f4c, 0x91142a86ae5241b2 },
    .tag_gmac_128 = { 0x43dadd5ecee9674b, 0xa30fea9ae8091c6c },
    .tag_gmac_256 = { 0xc360b76ac1887181, 0xcb732f29ea86edeb },
  },
  {
    .n_bytes = 16385,
    .tag_gcm_128 = { 0xe2a47837578b4056, 0xf96e7233cbeb1ce1 },
    .tag_gcm_256 = { 0xfa3aa4ebe36fb390, 0x6a2cf1671f4f1a01 },
    .tag_gmac_128 = { 0xfd0b7312c4975687, 0xdd3096b1c850e80a },
    .tag_gmac_256 = { 0xaf2cae4642a5536a, 0xb27aff5cc8bd354c },
  },
  {
    .n_bytes = 16386,
    .tag_gcm_128 = { 0xe1b4c0e5825304ae, 0x48c5dd82aa114320 },
    .tag_gcm_256 = { 0x76c3612118f47fa8, 0xdd0a47b132ecad3a },
    .tag_gmac_128 = { 0x346bc841a7f5b642, 0x6fb1b96391c66b40 },
    .tag_gmac_256 = { 0x2f1a1b6a000e18b2, 0xf7cba25e02551d43 },
  },
};

#define MAX_TEST_DATA_LEN 32768

static const struct
{
  char *name;
  const u8 *pt, *key128, *key256, *ct128, *ct256, *tag128, *tag256, *aad, *iv;
  u32 data_len, tag128_len, tag256_len, aad_len;
} test_cases[] = {
  /* test cases */
  {
    .name = "GCM Spec. TC1",
    .iv = tc1_iv,
    .key128 = tc1_key128,
    .key256 = tc1_key256,
    .tag128 = tc1_tag128,
    .tag128_len = sizeof (tc1_tag128),
    .tag256 = tc1_tag256,
    .tag256_len = sizeof (tc1_tag256),
  },
  {
    .name = "GCM Spec. TC2",
    .pt = tc2_plaintext,
    .data_len = sizeof (tc2_plaintext),
    .iv = tc1_iv,
    .key128 = tc1_key128,
    .key256 = tc1_key256,
    .ct128 = tc2_ciphertext128,
    .ct256 = tc2_ciphertext256,
    .tag128 = tc2_tag128,
    .tag128_len = sizeof (tc2_tag128),
    .tag256 = tc2_tag256,
    .tag256_len = sizeof (tc2_tag256),
  },
  {
    .name = "GCM Spec. TC3",
    .pt = tc3_plaintext,
    .data_len = sizeof (tc3_plaintext),
    .iv = tc3_iv,
    .key128 = tc3_key128,
    .key256 = tc3_key256,
    .ct128 = tc3_ciphertext128,
    .ct256 = tc3_ciphertext256,
    .tag128 = tc3_tag128,
    .tag128_len = sizeof (tc3_tag128),
    .tag256 = tc3_tag256,
    .tag256_len = sizeof (tc3_tag256),
  },
  {
    .name = "GCM Spec. TC4",
    .pt = tc4_plaintext,
    .data_len = sizeof (tc4_plaintext),
    .aad = tc4_aad,
    .aad_len = sizeof (tc4_aad),
    .iv = tc3_iv,
    .key128 = tc3_key128,
    .key256 = tc3_key256,
    .ct128 = tc4_ciphertext128,
    .ct256 = tc4_ciphertext256,
    .tag128 = tc4_tag128,
    .tag128_len = sizeof (tc4_tag128),
    .tag256 = tc4_tag256,
    .tag256_len = sizeof (tc4_tag256),
  }
};

#define perftest_aesXXX_enc_var_sz(a)                                         \
  void __test_perf_fn perftest_aes##a##_enc_var_sz (test_perf_t *tp)          \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_gcm_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    u8 *tag = test_mem_alloc (16);                                            \
    u8 *key = test_mem_alloc_and_fill_inc_u8 (32, 192, 0);                    \
    u8 *iv = test_mem_alloc_and_fill_inc_u8 (16, 128, 0);                     \
                                                                              \
    clib_aes_gcm_key_expand (kd, key, AES_KEY_##a);                           \
                                                                              \
    test_perf_event_enable (tp);                                              \
    clib_aes##a##_gcm_enc (kd, src, n, 0, 0, iv, 16, dst, tag);               \
    test_perf_event_disable (tp);                                             \
  }

#define perftest_aesXXX_dec_var_sz(a)                                         \
  void __test_perf_fn perftest_aes##a##_dec_var_sz (test_perf_t *tp)          \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_gcm_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    u8 *tag = test_mem_alloc (16);                                            \
    u8 *key = test_mem_alloc_and_fill_inc_u8 (32, 192, 0);                    \
    u8 *iv = test_mem_alloc_and_fill_inc_u8 (16, 128, 0);                     \
    int *rv = test_mem_alloc (16);                                            \
                                                                              \
    clib_aes_gcm_key_expand (kd, key, AES_KEY_##a);                           \
                                                                              \
    test_perf_event_enable (tp);                                              \
    rv[0] = clib_aes##a##_gcm_dec (kd, src, n, 0, 0, iv, tag, 16, dst);       \
    test_perf_event_disable (tp);                                             \
  }

static clib_error_t *
test_clib_aes128_gcm_enc (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 pt[MAX_TEST_DATA_LEN];
  u8 ct[MAX_TEST_DATA_LEN];
  u8 tag[16];

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key128, AES_KEY_128);
      clib_aes128_gcm_enc (&kd, tc->pt, tc->data_len, tc->aad, tc->aad_len,
			   tc->iv, tc->tag128_len, ct, tag);

      if (memcmp (tc->tag128, tag, tc->tag128_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->ct128, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  for (int i = 0; i < sizeof (pt); i++)
    pt[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_128);
  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      clib_aes128_gcm_enc (&kd, pt, tc->n_bytes, 0, 0, inc_iv, 16, ct, tag);

      if (memcmp (tc->tag_gcm_128, tag, 16) != 0)
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

perftest_aesXXX_enc_var_sz (128);

REGISTER_TEST (clib_aes128_gcm_enc) = {
  .name = "clib_aes128_gcm_enc",
  .fn = test_clib_aes128_gcm_enc,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes128_enc_var_sz }),
};

static clib_error_t *
test_clib_aes256_gcm_enc (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 pt[MAX_TEST_DATA_LEN];
  u8 ct[MAX_TEST_DATA_LEN];
  u8 tag[16];

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key256, AES_KEY_256);
      clib_aes256_gcm_enc (&kd, tc->pt, tc->data_len, tc->aad, tc->aad_len,
			   tc->iv, tc->tag256_len, ct, tag);

      if (memcmp (tc->tag256, tag, tc->tag256_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->ct256, ct, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  for (int i = 0; i < sizeof (pt); i++)
    pt[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_256);
  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      clib_aes256_gcm_enc (&kd, pt, tc->n_bytes, 0, 0, inc_iv, 16, ct, tag);

      if (memcmp (tc->tag_gcm_256, tag, 16) != 0)
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

perftest_aesXXX_enc_var_sz (256);
REGISTER_TEST (clib_aes256_gcm_enc) = {
  .name = "clib_aes256_gcm_enc",
  .fn = test_clib_aes256_gcm_enc,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes256_enc_var_sz }),
};

static clib_error_t *
test_clib_aes128_gcm_dec (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 pt[MAX_TEST_DATA_LEN];
  u8 ct[MAX_TEST_DATA_LEN];
  u8 tag[16];
  int rv;

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key128, AES_KEY_128);
      rv = clib_aes128_gcm_dec (&kd, tc->ct128, tc->data_len, tc->aad,
				tc->aad_len, tc->iv, tc->tag128,
				tc->tag128_len, pt);

      if (!rv)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->pt, pt, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  for (int i = 0; i < sizeof (pt); i++)
    pt[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_128);
  clib_aes128_gcm_enc (&kd, pt, sizeof (ct), 0, 0, inc_iv, 16, ct, tag);

  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      if (!clib_aes128_gcm_dec (&kd, ct, tc->n_bytes, 0, 0, inc_iv,
				(u8 *) tc->tag_gcm_128, 16, pt))
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

perftest_aesXXX_dec_var_sz (128);

REGISTER_TEST (clib_aes128_gcm_dec) = {
  .name = "clib_aes128_gcm_dec",
  .fn = test_clib_aes128_gcm_dec,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes128_dec_var_sz }),
};

static clib_error_t *
test_clib_aes256_gcm_dec (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 pt[MAX_TEST_DATA_LEN];
  u8 ct[MAX_TEST_DATA_LEN];
  u8 tag[16];
  int rv;

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key256, AES_KEY_256);
      rv = clib_aes256_gcm_dec (&kd, tc->ct256, tc->data_len, tc->aad,
				tc->aad_len, tc->iv, tc->tag256,
				tc->tag256_len, pt);

      if (!rv)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->pt, pt, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  for (int i = 0; i < sizeof (pt); i++)
    pt[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_128);
  clib_aes128_gcm_enc (&kd, pt, sizeof (ct), 0, 0, inc_iv, 16, ct, tag);

  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      if (!clib_aes128_gcm_dec (&kd, ct, tc->n_bytes, 0, 0, inc_iv,
				(u8 *) tc->tag_gcm_128, 16, pt))
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

perftest_aesXXX_dec_var_sz (256);
REGISTER_TEST (clib_aes256_gcm_dec) = {
  .name = "clib_aes256_gcm_dec",
  .fn = test_clib_aes256_gcm_dec,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes256_dec_var_sz }),
};

static const u8 gmac1_key[] = {
  0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
  0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb
};
static const u8 gmac1_iv[] = { 0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7,
			       0xba, 0x01, 0x36, 0xa7, 0x97, 0xf3 };
static const u8 gmac1_aad[] = {
  0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
  0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab
};
static const u8 gmac1_tag[] = {
  0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
  0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46
};

static const u8 gmac2_key[] = {
  0x20, 0xb5, 0xb6, 0xb8, 0x54, 0xe1, 0x87, 0xb0,
  0x58, 0xa8, 0x4d, 0x57, 0xbc, 0x15, 0x38, 0xb6
};

static const u8 gmac2_iv[] = { 0x94, 0xc1, 0x93, 0x5a, 0xfc, 0x06,
			       0x1c, 0xbf, 0x25, 0x4b, 0x93, 0x6f };

static const u8 gmac2_aad[] = {
  0xca, 0x41, 0x8e, 0x71, 0xdb, 0xf8, 0x10, 0x03, 0x81, 0x74, 0xea, 0xa3, 0x71,
  0x9b, 0x3f, 0xcb, 0x80, 0x53, 0x1c, 0x71, 0x10, 0xad, 0x91, 0x92, 0xd1, 0x05,
  0xee, 0xaa, 0xfa, 0x15, 0xb8, 0x19, 0xac, 0x00, 0x56, 0x68, 0x75, 0x2b, 0x34,
  0x4e, 0xd1, 0xb2, 0x2f, 0xaf, 0x77, 0x04, 0x8b, 0xaf, 0x03, 0xdb, 0xdd, 0xb3,
  0xb4, 0x7d, 0x6b, 0x00, 0xe9, 0x5c, 0x4f, 0x00, 0x5e, 0x0c, 0xc9, 0xb7, 0x62,
  0x7c, 0xca, 0xfd, 0x3f, 0x21, 0xb3, 0x31, 0x2a, 0xa8, 0xd9, 0x1d, 0x3f, 0xa0,
  0x89, 0x3f, 0xe5, 0xbf, 0xf7, 0xd4, 0x4c, 0xa4, 0x6f, 0x23, 0xaf, 0xe0
};

static const u8 gmac2_tag[] = {
  0xb3, 0x72, 0x86, 0xeb, 0xaf, 0x4a, 0x54, 0xe0,
  0xff, 0xc2, 0xa1, 0xde, 0xaf, 0xc9, 0xf6, 0xdb
};

static const struct
{
  char *name;
  const u8 *key128, *key256, *tag128, *tag256, *aad, *iv;
  u32 tag128_len, tag256_len, aad_len;
} gmac_test_cases[] = {
  /* test cases */
  {
    .name = "GMAC1",
    .iv = gmac1_iv,
    .key128 = gmac1_key,
    .tag128 = gmac1_tag,
    .tag128_len = sizeof (gmac1_tag),
    .aad = gmac1_aad,
    .aad_len = sizeof (gmac1_aad),
  },
  {
    .name = "GMAC2",
    .iv = gmac2_iv,
    .key128 = gmac2_key,
    .tag128 = gmac2_tag,
    .tag128_len = sizeof (gmac2_tag),
    .aad = gmac2_aad,
    .aad_len = sizeof (gmac2_aad),
  },
};

static clib_error_t *
test_clib_aes128_gmac (clib_error_t *err)
{
  u8 data[MAX_TEST_DATA_LEN];
  aes_gcm_key_data_t kd;
  u8 tag[16];

  FOREACH_ARRAY_ELT (tc, gmac_test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key128, AES_KEY_128);
      clib_aes128_gmac (&kd, tc->aad, tc->aad_len, tc->iv, tc->tag128_len,
			tag);

      if (memcmp (tc->tag128, tag, tc->tag128_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);
    }

  for (int i = 0; i < sizeof (data); i++)
    data[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_128);
  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      clib_aes128_gmac (&kd, data, tc->n_bytes, inc_iv, 16, tag);

      if (memcmp (tc->tag_gmac_128, tag, 16) != 0)
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

void __test_perf_fn
perftest_gmac256_fixed_512byte (test_perf_t *tp)
{
  uword n = tp->n_ops;
  aes_gcm_key_data_t *kd = test_mem_alloc (sizeof (aes_gcm_key_data_t));
  u8 *ivs = test_mem_alloc_and_fill_inc_u8 (n * 12, 0, 0);
  u8 *tags = test_mem_alloc_and_fill_inc_u8 (8 + n * 16, 0, 0);
  u8 *data = test_mem_alloc_and_fill_inc_u8 (512, 0, 0);

  test_perf_event_enable (tp);
  clib_aes_gcm_key_expand (kd, inc_key, AES_KEY_128);

  for (int i = 0; i < n; i++)
    clib_aes128_gmac (kd, data, 512, ivs + n * 12, 16, tags + n * 16);
  test_perf_event_disable (tp);
}

REGISTER_TEST (clib_aes128_gmac) = {
  .name = "clib_aes128_gmac",
  .fn = test_clib_aes128_gmac,
  .perf_tests = PERF_TESTS ({ .name = "fixed (512 byte)",
			      .n_ops = 256,
			      .fn = perftest_gmac256_fixed_512byte }),
};

static clib_error_t *
test_clib_aes256_gmac (clib_error_t *err)
{
  u8 data[MAX_TEST_DATA_LEN];
  aes_gcm_key_data_t kd;
  u8 tag[16];

#if 0
  FOREACH_ARRAY_ELT (tc, gmac_test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key256, AES_KEY_256);
      clib_aes256_gmac (&kd, tc->aad, tc->aad_len, tc->iv, tc->tag256_len,
			tag);

      if (memcmp (tc->tag256, tag, tc->tag256_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);
    }
#endif

  for (int i = 0; i < sizeof (data); i++)
    data[i] = i;

  clib_aes_gcm_key_expand (&kd, inc_key, AES_KEY_256);
  FOREACH_ARRAY_ELT (tc, inc_test_cases)
    {
      clib_aes256_gmac (&kd, data, tc->n_bytes, inc_iv, 16, tag);

      if (memcmp (tc->tag_gmac_256, tag, 16) != 0)
	return clib_error_return (err, "incremental %u bytes: invalid tag",
				  tc->n_bytes);
    }

  return err;
}

REGISTER_TEST (clib_aes256_gmac) = {
  .name = "clib_aes256_gmac",
  .fn = test_clib_aes256_gmac,
};
#endif
