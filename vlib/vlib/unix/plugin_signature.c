/*
 * plugin.c: plugin handling
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <vlib/unix/plugin.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* 
 * Extract these bits from a .pem file as follows:
 * 
 * openssl rsa -in <mykeys.pem> -out <textfile> -pubout -modulus -text
 * 
 * pubkey_N shows up in <textfile> as "Modulus=<long-hex-string>",
 * right before -----BEGIN PUBLIC KEY-----
 *
 * pubkey_E shows up as "publicExponent: <decimal>(<hex>)", right
 * after the (private) key modulus. Seems to be constant, 0x10001.
 */
static const char *pubkey_N =
    "CA22EE625A5A70FBE46B885BCDCFF2EB113933A4FF393FEE648FCE65914EC0BB001DEE8AACB3F325677805CB85C9C5C864E96AA7B0B1C1A847337DD4E278F5EEC625236F0A35F8FFCB19FB6EB155DC00A3BD73329D1208CBF99213583729AD4DCEEF0837020D991B9D372DC5E7A41692899F5483BA8675E1EAD30FCE8B04C75E3800380B2B6767B8A265DD9AC669B160A9D039936C59DE71152D49C1F2D0096A93375CD095E2482136F7D3480C637FCCB0928A3DA6AF3909D18E23D212F000362E255D2ECC102B32FA72875A681BF9AD05CD2F74A6D9F8095DAE0507B9569102E5E6E33E904A90B8E46446D750D1A88F42A878469483FA153A4628BB4770C9EB"; 
static const char *pubkey_E = "010001";

/*
 * decrypt_exec_signature
 * Use the mbedtls library to recover the image signature
 */
static int
decrypt_signature (u8 * inbuf, int in_len, u8 * outbuf, int out_len)
{
  mbedtls_rsa_context rsa;
  int olen;
  unsigned char *p;
  u8 *op;
  u8 * decrypt_here = 0;

  vec_validate (decrypt_here, 511);

  mbedtls_rsa_init (&rsa, MBEDTLS_RSA_PKCS_V15, 0 /* hash_id, ignored */);

  if (mbedtls_mpi_read_string (&rsa.N, 16, (char *) pubkey_N))
    return -1;
  if (mbedtls_mpi_read_string (&rsa.E, 16, (char *) pubkey_E))
    return -2;

  rsa.len = (mbedtls_mpi_bitlen (&rsa.N) + 7) >> 3;

  if (rsa.len >= vec_len(decrypt_here))
    return -3;

  mbedtls_rsa_public (&rsa, (unsigned char *) inbuf, decrypt_here);

  /* NULL-terminate the result */
  decrypt_here[rsa.len] = 0;

  /* 
   * Strip padding. Padding is required to stop a 
   * variety of crypto attacks.
   */
  p = decrypt_here;
  if (*p++ != 0 || *p++ != 1)
    {
      vec_free(decrypt_here);
      return (-4);
    }

  while (*p != 0)
    {
      if ((p >= decrypt_here + vec_len(decrypt_here) - 1) || *p != 0xFF)
        {
          vec_free(decrypt_here);
          return (-5);
        }
      p++;
    }
  p++;
  op = outbuf;
  olen = 0;

  while (*p && olen < out_len)
    {
      *op++ = *p++;
      olen++;
    }
  if (olen == out_len)
    op -= 1;
  *op = 0;

  return (olen);
}

/*
 * sha256_check
 * Compute the sha2sum of a signed binary, compare with the
 * decrypted signature.
 */
static int
sha256_check (int fd, off_t nbytes, u8 *decrypted_signature)
{
  u32 nbytes_this_transfer;
  uword nbytes_left = nbytes;
  uword offset;
  static u8 buf[4096];
  u8 sha2sum[32];
  u8 c, digit;
  u8 *tmp;
  mbedtls_sha256_context ctx;
  int i;
  int rv;

  mbedtls_sha256_starts (&ctx, 0 /* is224 = 0, we want sha256 */ );
  offset = 0;

  lseek (fd, 0L, SEEK_SET);

  while (nbytes_left > 0)
    {
      if (nbytes_left > sizeof (buf))
	nbytes_this_transfer = sizeof (buf);
      else
	nbytes_this_transfer = nbytes_left;

      rv = read (fd, buf, nbytes_this_transfer);
      if (rv < 0)
	{
	  clib_unix_warning ("offset 0x%lx rv %u", (uword) offset, rv);
	  return -11;
	}
      mbedtls_sha256_update (&ctx, buf, nbytes_this_transfer);
      nbytes_left -= nbytes_this_transfer;
      offset += nbytes_this_transfer;
    }
  mbedtls_sha256_finish (&ctx, sha2sum);

  /* 
   * Check the computed sha2 sum against the decrypted
   * signature "from the factory." 
   * The decrypted signature is in text form:
   * (stdin)= 8b7de297bb352188fddf6aa1c59a6966dc13122806736194572f49cee38dcf17\n
   */
  tmp = decrypted_signature + 9; /* skip "(stdin)= " */
  for (i = 0; i < 32; i++)
    {
      c = *tmp++;
      digit = 0;		/* to shut up gcc */
      if (c >= '0' && c <= '9')
	digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	digit = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
	digit = c - 'A' + 10;
      c = *tmp++;
      digit <<= 4;
      if (c >= '0' && c <= '9')
	digit |= c - '0';
      else if (c >= 'a' && c <= 'f')
	digit |= c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
	digit |= c - 'A' + 10;

      if (sha2sum[i] != digit)
	{
	  clib_warning ("[%u] 0x%x vs 0x%x\n", i, sha2sum[i], digit);
	  return -13;
	}
    }
  return 1;
}

/*
 * check_exec_signature
 * Look for the union label
 */
int
vlib_check_plugin_signature (char *filename)
{
  int fd;
  off_t offset, sig_begins_at;
  static u8 *sigbuf = 0;
  static u8 *outbuf = 0;
  u32 sig_len;
  u8 buf[4];
  int rv;
  struct stat st;

  fd = open (filename, O_RDONLY, 0);
  if (fd < 0)
    {
      clib_warning ("couldn't open %s", filename);
      return 1;
    }

  if ((fstat (fd, &st) < 0) || (st.st_size < 4))
    {
      clib_unix_warning ("fstat");
      return 1;
    }

  offset = st.st_size - 4;

  lseek (fd, offset, SEEK_SET);

  rv = read (fd, buf, 4);
  if (rv != 4)
    {
      clib_unix_warning ("read: offset 0x%lx rv %u\n", (uword) offset, rv);
      return 1;
    }

  /* recover signature (if any) */
  sig_len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3] << 0);

  /*
   * unstripped, unsigned executables have unpredictable junk
   * (symbols) preceeding EOF
   */
  if ((4 + sig_len) > st.st_size)
    {
      clib_warning ("unsigned executable: %s\n", filename);
      return 1;
    }

  /* 
   * Hard signature size limits. Stripped unsigned images
   * most often fail right here.
   */
  if (sig_len < 0x10 || sig_len > 0x100)
    {
      clib_warning ("unsigned executable: %s\n", filename);
      return 1;
    }

  sig_begins_at = st.st_size - (4 + sig_len);

  vec_validate (sigbuf, sig_len - 1);
  lseek (fd, sig_begins_at, SEEK_SET);
  rv = read (fd, sigbuf, sig_len);
  if (rv != sig_len)
    {
      clib_unix_warning ("read signature: rv %u\n", rv);
      return 1;
    }

  vec_validate (outbuf, sig_len - 1);
  memset (outbuf, 0, sig_len);
  rv = decrypt_signature (sigbuf, vec_len (sigbuf), outbuf, vec_len (outbuf));

  if (rv < 0)
    {
      clib_warning ("bad signature: %s\n", filename);
      return 1;
    }

  rv = sha256_check (fd, sig_begins_at, outbuf);

  if (rv < 0)
    {
      clib_warning ("altered executable: %s\n", filename);
      return 1;
    }

  clib_warning ("good sha256 signature: %s\n", filename);

  return 0;
}
