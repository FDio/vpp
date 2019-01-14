/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

/* from RFC7296 */
static const char modp_dh_768_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
static const char modp_dh_768_generator[] = "02";

static const char modp_dh_1024_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" "FFFFFFFFFFFFFFFF";
static const char modp_dh_1024_generator[] = "02";

/* from RFC3526 */
static const char modp_dh_1536_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
static const char modp_dh_1536_generator[] = "02";

static const char modp_dh_2048_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
static const char modp_dh_2048_generator[] = "02";

static const char modp_dh_3072_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
static const char modp_dh_3072_generator[] = "02";

static const char modp_dh_4096_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" "FFFFFFFFFFFFFFFF";
static const char modp_dh_4096_generator[] = "02";

static const char modp_dh_6144_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
  "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
  "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
  "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
  "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
  "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
  "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
  "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
  "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
  "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
  "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
  "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
  "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
  "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
  "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
  "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
  "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
  "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
  "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
  "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
  "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
  "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
  "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
  "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
  "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
  "6DCC4024FFFFFFFFFFFFFFFF";
static const char modp_dh_6144_generator[] = "02";

static const char modp_dh_8192_prime[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
  "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
  "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
  "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
  "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
  "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
  "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
  "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
  "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
  "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
  "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
  "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
  "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
  "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
  "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
  "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
  "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
  "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
  "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
  "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
  "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
  "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
  "60C980DD98EDD3DFFFFFFFFFFFFFFFFF";
static const char modp_dh_8192_generator[] = "02";

/* from RFC5114 */
static const char modp_dh_1024_160_prime[] =
  "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
  "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
  "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
  "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
  "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" "DF1FB2BC2E4A4371";
static const char modp_dh_1024_160_generator[] =
  "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
  "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
  "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
  "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
  "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" "855E6EEB22B3B2E5";

static const char modp_dh_2048_224_prime[] =
  "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1"
  "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15"
  "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212"
  "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
  "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708"
  "B3BF8A317091883681286130BC8985DB1602E714415D9330"
  "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D"
  "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
  "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763"
  "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71"
  "CF9DE5384E71B81C0AC4DFFE0C10E64F";
static const char modp_dh_2048_224_generator[] =
  "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF"
  "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA"
  "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7"
  "C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
  "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE"
  "F180EB34118E98D119529A45D6F834566E3025E316A330EF"
  "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB"
  "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
  "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269"
  "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179"
  "81BC087F2A7065B384B890D3191F2BFA";

static const char modp_dh_2048_256_prime[] =
  "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
  "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
  "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
  "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
  "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
  "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
  "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
  "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
  "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
  "75F26375D7014103A4B54330C198AF126116D2276E11715F"
  "693877FAD7EF09CADB094AE91E1A1597";
static const char modp_dh_2048_256_generator[] =
  "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054"
  "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555"
  "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18"
  "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
  "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83"
  "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55"
  "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14"
  "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
  "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6"
  "184B523D1DB246C32F63078490F00EF8D647D148D4795451"
  "5E2327CFEF98C582664B4C0F6CC41659";

v8 *
ikev2_calc_prf (ikev2_sa_transform_t * tr, v8 * key, v8 * data)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *ctx;
#else
  HMAC_CTX ctx;
#endif
  v8 *prf;
  unsigned int len = 0;

  prf = vec_new (u8, tr->key_trunc);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = HMAC_CTX_new ();
  HMAC_Init_ex (ctx, key, vec_len (key), tr->md, NULL);
  HMAC_Update (ctx, data, vec_len (data));
  HMAC_Final (ctx, prf, &len);
#else
  HMAC_CTX_init (&ctx);
  HMAC_Init_ex (&ctx, key, vec_len (key), tr->md, NULL);
  HMAC_Update (&ctx, data, vec_len (data));
  HMAC_Final (&ctx, prf, &len);
  HMAC_CTX_cleanup (&ctx);
#endif
  ASSERT (len == tr->key_trunc);

  return prf;
}

u8 *
ikev2_calc_prfplus (ikev2_sa_transform_t * tr, u8 * key, u8 * seed, int len)
{
  v8 *t = 0, *s = 0, *tmp = 0, *ret = 0;
  u8 x = 0;

  /* prf+ (K,S) = T1 | T2 | T3 | T4 | ...

     where:
     T1 = prf (K, S | 0x01)
     T2 = prf (K, T1 | S | 0x02)
     T3 = prf (K, T2 | S | 0x03)
     T4 = prf (K, T3 | S | 0x04)
   */

  while (vec_len (ret) < len && x < 255)
    {
      if (t)
	{
	  vec_append (s, t);
	  vec_free (t);
	}

      vec_append (s, seed);
      vec_add2 (s, tmp, 1);
      *tmp = x + 1;
      t = ikev2_calc_prf (tr, key, s);
      vec_append (ret, t);
      vec_free (s);
      x++;
    }

  vec_free (t);

  if (x == 255)
    {
      vec_free (ret);
    }

  return ret;
}

v8 *
ikev2_calc_integr (ikev2_sa_transform_t * tr, v8 * key, u8 * data, int len)
{
  v8 *r;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *hctx;
#else
  HMAC_CTX hctx;
#endif
  unsigned int l;

  ASSERT (tr->type == IKEV2_TRANSFORM_TYPE_INTEG);

  r = vec_new (u8, tr->key_len);

  if (tr->md == EVP_sha1 ())
    {
      clib_warning ("integrity checking with sha1");
    }
  else if (tr->md == EVP_sha256 ())
    {
      clib_warning ("integrity checking with sha256");
    }

  /* verify integrity of data */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  hctx = HMAC_CTX_new ();
  HMAC_Init_ex (hctx, key, vec_len (key), tr->md, NULL);
  HMAC_Update (hctx, (const u8 *) data, len);
  HMAC_Final (hctx, r, &l);
#else
  HMAC_CTX_init (&hctx);
  HMAC_Init_ex (&hctx, key, vec_len (key), tr->md, NULL);
  HMAC_Update (&hctx, (const u8 *) data, len);
  HMAC_Final (&hctx, r, &l);
  HMAC_CTX_cleanup (&hctx);
#endif

  ASSERT (l == tr->key_len);

  return r;
}

v8 *
ikev2_decrypt_data (ikev2_sa_t * sa, u8 * data, int len)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx;
#else
  EVP_CIPHER_CTX ctx;
#endif
  v8 *r;
  int out_len = 0, block_size;
  ikev2_sa_transform_t *tr_encr;
  u8 *key = sa->is_initiator ? sa->sk_er : sa->sk_ei;

  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  block_size = tr_encr->block_size;

  /* check if data is multiplier of cipher block size */
  if (len % block_size)
    {
      clib_warning ("wrong data length");
      return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = EVP_CIPHER_CTX_new ();
#else
  EVP_CIPHER_CTX_init (&ctx);
#endif

  r = vec_new (u8, len - block_size);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_DecryptInit_ex (ctx, tr_encr->cipher, NULL, key, data);
  EVP_DecryptUpdate (ctx, r, &out_len, data + block_size, len - block_size);
  EVP_DecryptFinal_ex (ctx, r + out_len, &out_len);
#else
  EVP_DecryptInit_ex (&ctx, tr_encr->cipher, NULL, key, data);
  EVP_DecryptUpdate (&ctx, r, &out_len, data + block_size, len - block_size);
  EVP_DecryptFinal_ex (&ctx, r + out_len, &out_len);
#endif
  /* remove padding */
  _vec_len (r) -= r[vec_len (r) - 1] + 1;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_CIPHER_CTX_cleanup (&ctx);
#endif
  return r;
}

int
ikev2_encrypt_data (ikev2_sa_t * sa, v8 * src, u8 * dst)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx;
#else
  EVP_CIPHER_CTX ctx;
#endif
  int out_len;
  int bs;
  ikev2_sa_transform_t *tr_encr;
  u8 *key = sa->is_initiator ? sa->sk_ei : sa->sk_er;

  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  bs = tr_encr->block_size;

  /* generate IV */
  RAND_bytes (dst, bs);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = EVP_CIPHER_CTX_new ();
  EVP_EncryptInit_ex (ctx, tr_encr->cipher, NULL, key, dst /* dst */ );
  EVP_EncryptUpdate (ctx, dst + bs, &out_len, src, vec_len (src));
#else
  EVP_CIPHER_CTX_init (&ctx);
  EVP_EncryptInit_ex (&ctx, tr_encr->cipher, NULL, key, dst /* dst */ );
  EVP_EncryptUpdate (&ctx, dst + bs, &out_len, src, vec_len (src));
  EVP_CIPHER_CTX_cleanup (&ctx);
#endif

  ASSERT (vec_len (src) == out_len);

  return out_len + bs;
}

void
ikev2_generate_dh (ikev2_sa_t * sa, ikev2_sa_transform_t * t)
{
  int r;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  BIGNUM *p = BN_new ();
  BIGNUM *q = BN_new ();
  BIGNUM *g = BN_new ();
  BIGNUM *pub_key = BN_new ();
  BIGNUM *priv_key = BN_new ();
#endif

  if (t->dh_group == IKEV2_DH_GROUP_MODP)
    {
      DH *dh = DH_new ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      BN_hex2bn (&p, t->dh_p);
      BN_hex2bn (&g, t->dh_g);
      DH_set0_pqg (dh, p, q, g);
#else
      BN_hex2bn (&dh->p, t->dh_p);
      BN_hex2bn (&dh->g, t->dh_g);
#endif
      DH_generate_key (dh);

      if (sa->is_initiator)
	{
	  sa->i_dh_data = vec_new (u8, t->key_len);
	  sa->dh_private_key = vec_new (u8, t->key_len);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	  r = BN_bn2bin (pub_key, sa->i_dh_data);
	  ASSERT (r == t->key_len);
	  r = BN_bn2bin (priv_key, sa->dh_private_key);
	  DH_set0_key (dh, pub_key, priv_key);
#else
	  r = BN_bn2bin (dh->pub_key, sa->i_dh_data);
	  ASSERT (r == t->key_len);
	  r = BN_bn2bin (dh->priv_key, sa->dh_private_key);
	  ASSERT (r == t->key_len);
#endif
	}
      else
	{
	  sa->r_dh_data = vec_new (u8, t->key_len);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	  r = BN_bn2bin (pub_key, sa->i_dh_data);
	  ASSERT (r == t->key_len);
	  DH_set0_key (dh, pub_key, NULL);
#else
	  r = BN_bn2bin (dh->pub_key, sa->r_dh_data);
	  ASSERT (r == t->key_len);
#endif
	  BIGNUM *ex;
	  sa->dh_shared_key = vec_new (u8, t->key_len);
	  ex = BN_bin2bn (sa->i_dh_data, vec_len (sa->i_dh_data), NULL);
	  r = DH_compute_key (sa->dh_shared_key, ex, dh);
	  ASSERT (r == t->key_len);
	  BN_clear_free (ex);
	}
      DH_free (dh);
    }
  else if (t->dh_group == IKEV2_DH_GROUP_ECP)
    {
      EC_KEY *ec = EC_KEY_new_by_curve_name (t->nid);
      ASSERT (ec);

      EC_KEY_generate_key (ec);

      const EC_POINT *r_point = EC_KEY_get0_public_key (ec);
      const EC_GROUP *group = EC_KEY_get0_group (ec);
      BIGNUM *x = NULL, *y = NULL;
      BN_CTX *bn_ctx = BN_CTX_new ();
      u16 x_off, y_off, len;
      EC_POINT *i_point = EC_POINT_new (group);
      EC_POINT *shared_point = EC_POINT_new (group);

      x = BN_new ();
      y = BN_new ();
      len = t->key_len / 2;

      EC_POINT_get_affine_coordinates (group, r_point, x, y, bn_ctx);

      if (sa->is_initiator)
	{
	  sa->i_dh_data = vec_new (u8, t->key_len);
	  x_off = len - BN_num_bytes (x);
	  clib_memset (sa->i_dh_data, 0, x_off);
	  BN_bn2bin (x, sa->i_dh_data + x_off);
	  y_off = t->key_len - BN_num_bytes (y);
	  clib_memset (sa->i_dh_data + len, 0, y_off - len);
	  BN_bn2bin (y, sa->i_dh_data + y_off);

	  const BIGNUM *prv = EC_KEY_get0_private_key (ec);
	  sa->dh_private_key = vec_new (u8, BN_num_bytes (prv));
	  r = BN_bn2bin (prv, sa->dh_private_key);
	  ASSERT (r == BN_num_bytes (prv));
	}
      else
	{
	  sa->r_dh_data = vec_new (u8, t->key_len);
	  x_off = len - BN_num_bytes (x);
	  clib_memset (sa->r_dh_data, 0, x_off);
	  BN_bn2bin (x, sa->r_dh_data + x_off);
	  y_off = t->key_len - BN_num_bytes (y);
	  clib_memset (sa->r_dh_data + len, 0, y_off - len);
	  BN_bn2bin (y, sa->r_dh_data + y_off);

	  x = BN_bin2bn (sa->i_dh_data, len, x);
	  y = BN_bin2bn (sa->i_dh_data + len, len, y);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	  EC_POINT_set_affine_coordinates (group, i_point, x, y, bn_ctx);
#else
	  EC_POINT_set_affine_coordinates_GFp (group, i_point, x, y, bn_ctx);
#endif
	  sa->dh_shared_key = vec_new (u8, t->key_len);
	  EC_POINT_mul (group, shared_point, NULL, i_point,
			EC_KEY_get0_private_key (ec), NULL);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	  EC_POINT_get_affine_coordinates (group, shared_point, x, y, bn_ctx);
#else
	  EC_POINT_get_affine_coordinates_GFp (group, shared_point, x, y,
					       bn_ctx);
#endif
	  x_off = len - BN_num_bytes (x);
	  clib_memset (sa->dh_shared_key, 0, x_off);
	  BN_bn2bin (x, sa->dh_shared_key + x_off);
	  y_off = t->key_len - BN_num_bytes (y);
	  clib_memset (sa->dh_shared_key + len, 0, y_off - len);
	  BN_bn2bin (y, sa->dh_shared_key + y_off);
	}

      EC_KEY_free (ec);
      BN_free (x);
      BN_free (y);
      BN_CTX_free (bn_ctx);
      EC_POINT_free (i_point);
      EC_POINT_free (shared_point);
    }
}

void
ikev2_complete_dh (ikev2_sa_t * sa, ikev2_sa_transform_t * t)
{
  int r;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  BIGNUM *p = BN_new ();
  BIGNUM *q = BN_new ();
  BIGNUM *g = BN_new ();
  BIGNUM *priv_key = BN_new ();
#endif

  if (t->dh_group == IKEV2_DH_GROUP_MODP)
    {
      DH *dh = DH_new ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      BN_hex2bn (&p, t->dh_p);
      BN_hex2bn (&g, t->dh_g);
      DH_set0_pqg (dh, p, q, g);

      priv_key =
	BN_bin2bn (sa->dh_private_key, vec_len (sa->dh_private_key), NULL);
      DH_set0_key (dh, NULL, priv_key);
#else
      BN_hex2bn (&dh->p, t->dh_p);
      BN_hex2bn (&dh->g, t->dh_g);

      dh->priv_key =
	BN_bin2bn (sa->dh_private_key, vec_len (sa->dh_private_key), NULL);
#endif
      BIGNUM *ex;
      sa->dh_shared_key = vec_new (u8, t->key_len);
      ex = BN_bin2bn (sa->r_dh_data, vec_len (sa->r_dh_data), NULL);
      r = DH_compute_key (sa->dh_shared_key, ex, dh);
      ASSERT (r == t->key_len);
      BN_clear_free (ex);
      DH_free (dh);
    }
  else if (t->dh_group == IKEV2_DH_GROUP_ECP)
    {
      EC_KEY *ec = EC_KEY_new_by_curve_name (t->nid);
      ASSERT (ec);

      const EC_GROUP *group = EC_KEY_get0_group (ec);
      BIGNUM *x = NULL, *y = NULL;
      BN_CTX *bn_ctx = BN_CTX_new ();
      u16 x_off, y_off, len;
      BIGNUM *prv;

      prv =
	BN_bin2bn (sa->dh_private_key, vec_len (sa->dh_private_key), NULL);
      EC_KEY_set_private_key (ec, prv);

      x = BN_new ();
      y = BN_new ();
      len = t->key_len / 2;

      x = BN_bin2bn (sa->r_dh_data, len, x);
      y = BN_bin2bn (sa->r_dh_data + len, len, y);
      EC_POINT *r_point = EC_POINT_new (group);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
      EC_POINT_set_affine_coordinates (group, r_point, x, y, bn_ctx);
#else
      EC_POINT_set_affine_coordinates_GFp (group, r_point, x, y, bn_ctx);
#endif
      EC_KEY_set_public_key (ec, r_point);

      EC_POINT *i_point = EC_POINT_new (group);
      EC_POINT *shared_point = EC_POINT_new (group);

      x = BN_bin2bn (sa->i_dh_data, len, x);
      y = BN_bin2bn (sa->i_dh_data + len, len, y);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
      EC_POINT_set_affine_coordinates (group, i_point, x, y, bn_ctx);
#else
      EC_POINT_set_affine_coordinates_GFp (group, i_point, x, y, bn_ctx);
#endif
      EC_POINT_mul (group, shared_point, NULL, r_point,
		    EC_KEY_get0_private_key (ec), NULL);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
      EC_POINT_get_affine_coordinates (group, shared_point, x, y, bn_ctx);
#else
      EC_POINT_get_affine_coordinates_GFp (group, shared_point, x, y, bn_ctx);
#endif
      sa->dh_shared_key = vec_new (u8, t->key_len);
      x_off = len - BN_num_bytes (x);
      clib_memset (sa->dh_shared_key, 0, x_off);
      BN_bn2bin (x, sa->dh_shared_key + x_off);
      y_off = t->key_len - BN_num_bytes (y);
      clib_memset (sa->dh_shared_key + len, 0, y_off - len);
      BN_bn2bin (y, sa->dh_shared_key + y_off);

      EC_KEY_free (ec);
      BN_free (x);
      BN_free (y);
      BN_free (prv);
      BN_CTX_free (bn_ctx);
      EC_POINT_free (i_point);
      EC_POINT_free (r_point);
      EC_POINT_free (shared_point);
    }
}

int
ikev2_verify_sign (EVP_PKEY * pkey, u8 * sigbuf, u8 * data)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new ();
#else
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init (&md_ctx);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_VerifyInit (md_ctx, EVP_sha1 ());
  EVP_VerifyUpdate (md_ctx, data, vec_len (data));
#else
  EVP_VerifyInit_ex (&md_ctx, EVP_sha1 (), NULL);
  EVP_VerifyUpdate (&md_ctx, data, vec_len (data));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  return EVP_VerifyFinal (md_ctx, sigbuf, vec_len (sigbuf), pkey);
#else
  return EVP_VerifyFinal (&md_ctx, sigbuf, vec_len (sigbuf), pkey);
#endif
}

u8 *
ikev2_calc_sign (EVP_PKEY * pkey, u8 * data)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new ();
#else
  EVP_MD_CTX md_ctx;
#endif
  unsigned int sig_len = 0;
  u8 *sign;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_SignInit (md_ctx, EVP_sha1 ());
  EVP_SignUpdate (md_ctx, data, vec_len (data));
  /* get sign len */
  EVP_SignFinal (md_ctx, NULL, &sig_len, pkey);
  sign = vec_new (u8, sig_len);
  /* calc sign */
  EVP_SignFinal (md_ctx, sign, &sig_len, pkey);
#else
  EVP_SignInit (&md_ctx, EVP_sha1 ());
  EVP_SignUpdate (&md_ctx, data, vec_len (data));
  /* get sign len */
  EVP_SignFinal (&md_ctx, NULL, &sig_len, pkey);
  sign = vec_new (u8, sig_len);
  /* calc sign */
  EVP_SignFinal (&md_ctx, sign, &sig_len, pkey);
#endif
  return sign;
}

EVP_PKEY *
ikev2_load_cert_file (u8 * file)
{
  FILE *fp;
  X509 *x509;
  EVP_PKEY *pkey = NULL;

  fp = fopen ((char *) file, "r");
  if (!fp)
    {
      clib_warning ("open %s failed", file);
      goto end;
    }

  x509 = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp);
  if (x509 == NULL)
    {
      clib_warning ("read cert %s failed", file);
      goto end;
    }

  pkey = X509_get_pubkey (x509);
  if (pkey == NULL)
    clib_warning ("get pubkey %s failed", file);

end:
  return pkey;
}

EVP_PKEY *
ikev2_load_key_file (u8 * file)
{
  FILE *fp;
  EVP_PKEY *pkey = NULL;

  fp = fopen ((char *) file, "r");
  if (!fp)
    {
      clib_warning ("open %s failed", file);
      goto end;
    }

  pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  fclose (fp);
  if (pkey == NULL)
    clib_warning ("read %s failed", file);

end:
  return pkey;
}

void
ikev2_crypto_init (ikev2_main_t * km)
{
  ikev2_sa_transform_t *tr;

  /* vector of supported transforms - in order of preference */

  //Encryption

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_ENCR;
  tr->encr_type = IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC;
  tr->key_len = 256 / 8;
  tr->block_size = 128 / 8;
  tr->cipher = EVP_aes_256_cbc ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_ENCR;
  tr->encr_type = IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC;
  tr->key_len = 192 / 8;
  tr->block_size = 128 / 8;
  tr->cipher = EVP_aes_192_cbc ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_ENCR;
  tr->encr_type = IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC;
  tr->key_len = 128 / 8;
  tr->block_size = 128 / 8;
  tr->cipher = EVP_aes_128_cbc ();

  //PRF
  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_PRF;
  tr->prf_type = IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256;
  tr->key_len = 256 / 8;
  tr->key_trunc = 256 / 8;
  tr->md = EVP_sha256 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_PRF;
  tr->prf_type = IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_384;
  tr->key_len = 384 / 8;
  tr->key_trunc = 384 / 8;
  tr->md = EVP_sha384 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_PRF;
  tr->prf_type = IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_512;
  tr->key_len = 512 / 8;
  tr->key_trunc = 512 / 8;
  tr->md = EVP_sha512 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_PRF;
  tr->prf_type = IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA1;
  tr->key_len = 160 / 8;
  tr->key_trunc = 160 / 8;
  tr->md = EVP_sha1 ();

  //Integrity
  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_INTEG;
  tr->integ_type = IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128;
  tr->key_len = 256 / 8;
  tr->key_trunc = 128 / 8;
  tr->md = EVP_sha256 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_INTEG;
  tr->integ_type = IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192;
  tr->key_len = 384 / 8;
  tr->key_trunc = 192 / 8;
  tr->md = EVP_sha384 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_INTEG;
  tr->integ_type = IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256;
  tr->key_len = 512 / 8;
  tr->key_trunc = 256 / 8;
  tr->md = EVP_sha512 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_INTEG;
  tr->integ_type = IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_160;
  tr->key_len = 160 / 8;
  tr->key_trunc = 160 / 8;
  tr->md = EVP_sha1 ();

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_INTEG;
  tr->integ_type = IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96;
  tr->key_len = 160 / 8;
  tr->key_trunc = 96 / 8;
  tr->md = EVP_sha1 ();


#if defined(OPENSSL_NO_CISCO_FECDH)
  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_BRAINPOOL_512;
  tr->key_len = (512 * 2) / 8;
  tr->nid = NID_brainpoolP512r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_BRAINPOOL_384;
  tr->key_len = (384 * 2) / 8;
  tr->nid = NID_brainpoolP384r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_BRAINPOOL_256;
  tr->key_len = (256 * 2) / 8;
  tr->nid = NID_brainpoolP256r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_BRAINPOOL_224;
  tr->key_len = (224 * 2) / 8;
  tr->nid = NID_brainpoolP224r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_ECP_224;
  tr->key_len = (224 * 2) / 8;
  tr->nid = NID_secp224r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;
#endif

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_ECP_521;
  tr->key_len = (528 * 2) / 8;
  tr->nid = NID_secp521r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_ECP_384;
  tr->key_len = (384 * 2) / 8;
  tr->nid = NID_secp384r1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_ECP_256;
  tr->key_len = (256 * 2) / 8;
  tr->nid = NID_X9_62_prime256v1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_ECP_192;
  tr->key_len = (192 * 2) / 8;
  tr->nid = NID_X9_62_prime192v1;
  tr->dh_group = IKEV2_DH_GROUP_ECP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_2048_256;
  tr->key_len = 2048 / 8;
  tr->dh_p = (const char *) &modp_dh_2048_256_prime;
  tr->dh_g = (const char *) &modp_dh_2048_256_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_2048_224;
  tr->key_len = 2048 / 8;
  tr->dh_p = (const char *) &modp_dh_2048_224_prime;
  tr->dh_g = (const char *) &modp_dh_2048_224_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_1024_160;
  tr->key_len = 1024 / 8;
  tr->dh_p = (const char *) &modp_dh_1024_160_prime;
  tr->dh_g = (const char *) &modp_dh_1024_160_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_8192;
  tr->key_len = 8192 / 8;
  tr->dh_p = (const char *) &modp_dh_8192_prime;
  tr->dh_g = (const char *) &modp_dh_8192_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_6144;
  tr->key_len = 6144 / 8;
  tr->dh_p = (const char *) &modp_dh_6144_prime;
  tr->dh_g = (const char *) &modp_dh_6144_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_4096;
  tr->key_len = 4096 / 8;
  tr->dh_p = (const char *) &modp_dh_4096_prime;
  tr->dh_g = (const char *) &modp_dh_4096_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_3072;
  tr->key_len = 3072 / 8;
  tr->dh_p = (const char *) &modp_dh_3072_prime;
  tr->dh_g = (const char *) &modp_dh_3072_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_2048;
  tr->key_len = 2048 / 8;
  tr->dh_p = (const char *) &modp_dh_2048_prime;
  tr->dh_g = (const char *) &modp_dh_2048_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_1536;
  tr->key_len = 1536 / 8;
  tr->dh_p = (const char *) &modp_dh_1536_prime;
  tr->dh_g = (const char *) &modp_dh_1536_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_1024;
  tr->key_len = 1024 / 8;
  tr->dh_p = (const char *) &modp_dh_1024_prime;
  tr->dh_g = (const char *) &modp_dh_1024_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_DH;
  tr->dh_type = IKEV2_TRANSFORM_DH_TYPE_MODP_768;
  tr->key_len = 768 / 8;
  tr->dh_p = (const char *) &modp_dh_768_prime;
  tr->dh_g = (const char *) &modp_dh_768_generator;
  tr->dh_group = IKEV2_DH_GROUP_MODP;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_ESN;
  tr->esn_type = IKEV2_TRANSFORM_ESN_TYPE_ESN;

  vec_add2 (km->supported_transforms, tr, 1);
  tr->type = IKEV2_TRANSFORM_TYPE_ESN;
  tr->esn_type = IKEV2_TRANSFORM_ESN_TYPE_NO_ESN;
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
