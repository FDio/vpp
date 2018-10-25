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
/*
  Copyright (c) 2006 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/string.h>
#include <vppinfra/error.h>

/* Exchanges source and destination. */
void
clib_memswap (void *_a, void *_b, uword bytes)
{
  uword pa = pointer_to_uword (_a);
  uword pb = pointer_to_uword (_b);

#define _(TYPE)					\
  if (0 == ((pa | pb) & (sizeof (TYPE) - 1)))	\
    {						\
      TYPE * a = uword_to_pointer (pa, TYPE *);	\
      TYPE * b = uword_to_pointer (pb, TYPE *);	\
						\
      while (bytes >= 2*sizeof (TYPE))		\
	{					\
	  TYPE a0, a1, b0, b1;			\
	  bytes -= 2*sizeof (TYPE);		\
	  a += 2;				\
	  b += 2;				\
	  a0 = a[-2]; a1 = a[-1];		\
	  b0 = b[-2]; b1 = b[-1];		\
	  a[-2] = b0; a[-1] = b1;		\
	  b[-2] = a0; b[-1] = a1;		\
	}					\
      pa = pointer_to_uword (a);		\
      pb = pointer_to_uword (b);		\
    }

  if (BITS (uword) == BITS (u64))
    _(u64);
  _(u32);
  _(u16);
  _(u8);

#undef _

  ASSERT (bytes < 2);
  if (bytes)
    {
      u8 *a = uword_to_pointer (pa, u8 *);
      u8 *b = uword_to_pointer (pb, u8 *);
      u8 a0 = a[0], b0 = b[0];
      a[0] = b0;
      b[0] = a0;
    }
}

void
clib_c11_violation (const char *s)
{
  _clib_error (CLIB_ERROR_WARNING, (char *) __FUNCTION__, 0, (char *) s);
}

/**
 * @brief copy src to dest, at most n bytes, up to dmax
 *
 * @param *dest  pointer to memory to copy to
 * @param dmax   maximum length of resulting dest
 * @param *src   pointer to memory to copy from
 * @param n      maximum number of characters to copy from src
 *
 * @constraints  No null pointers
 *               n shall not be greater than dmax
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *
 */
errno_t
memcpy_s (void *__restrict__ dest, rsize_t dmax,
	  const void *__restrict__ src, rsize_t n)
{
  return memcpy_s_inline (dest, dmax, src, n);
}

/**
 * @brief set n bytes starting at s to the specified c value
 *
 * @param *s     pointer to memory to set the c value
 * @param smax   maximum length of resulting s
 * @param c      byte value
 * @param n      maximum number of characters to set in s
 *
 * @constraints  No null pointers
 *               n shall not be greater than smax
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *
 */
errno_t
memset_s (void *s, rsize_t smax, int c, rsize_t n)
{
  return memset_s_inline (s, smax, c, n);
}

/**
 * @brief compare memory until they differ, and their difference is returned in
 *        diff
 *
 * @param *s1     pointer to memory to compare against
 * @param s1max   maximum length of s1
 * @param *s2     pointer to memory to compare with s1
 * @param s2max   length of s2
 * @param *diff   pointer to the diff which is an integer greater than, equal to,
 *                or less than zero according to s1 is greater than, equal to,
 *                or less than s2.
 *
 * @constraints   No null pointers
 *                s1max and s2max shall not be zero
 *                s2max shall not be greater than s1max
 *
 * @return EOK    success
 *         diff   when the return code is EOK
 *         >0     s1 greater s2
 *          0     s1 == s2
 *         <0     s1 < s2
 *         EINVAL runtime constraint error
 *
 */
errno_t
memcmp_s (const void *s1, rsize_t s1max, const void *s2, rsize_t s2max,
	  int *diff)
{
  return memcmp_s_inline (s1, s1max, s2, s2max, diff);
}

/**
 * @brief compare string s2 to string s1, and their difference is returned in
 *        indicator
 *
 * @param *s1     pointer to string to compare against
 * @param s1max   maximum length of s1, excluding null
 * @param *s2     pointer to string to compare with s1
 * @param *indicator  pointer to the comparison result, which is an integer
 *                    greater than, equal to, or less than zero according to
 *                    s1 is greater than, equal to, or less than s2.
 *
 * @constraints   No null pointers
 *                s1max shall not be zero
 *                s1 shall be null terminated
 *
 * @return EOK        success
 *         indicator  when the return code is EOK
 *         >0         s1 greater s2
 *          0         s1 == s2
 *         <0         s1 < s2
 *         EINVAL     runtime constraint error
 *
 */
errno_t
strcmp_s (const char *s1, rsize_t s1max, const char *s2, int *indicator)
{
  return strcmp_s_inline (s1, s1max, s2, indicator);
}

/**
 * @brief compare string s2 to string s1, no more than n characters, and their
 *        difference is returned in indicator
 *
 * @param *s1     pointer to string to compare against
 * @param s1max   maximum length of s1, excluding null
 * @param *s2     pointer to string to compare with s1
 * @param n       maximum number of characters to compare
 * @param *indicator  pointer to the comparison result, which is an integer
 *                    greater than, equal to, or less than zero according to
 *                    s1 is greater than, equal to, or less than s2.
 *
 * @constraints   No null pointers
 *                s1max shall not be zero
 *                s1 shall be null terminated
 *                n shall not be greater than the smaller of s1max and strlen
 *                of s1
 *
 * @return EOK        success
 *         indicator  when the return code is EOK
 *         >0         s1 greater s2
 *          0         s1 == s2
 *         <0         s1 < s2
 *         EINVAL     runtime constraint error
 *
 */
errno_t
strncmp_s (const char *s1, rsize_t s1max, const char *s2, rsize_t n,
	   int *indicator)
{
  return strncmp_s_inline (s1, s1max, s2, n, indicator);
}

/**
 * @brief copy src string to dest string
 *
 * @param *dest  pointer to string to copy to
 * @param dmax   maximum length of resulting dest string, including null
 * @param *src   pointer to string to copy from
 *
 * @constraints  No null pointers
 *               dmax shall not be zero
 *               dmax shall be greater than string length of src
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *
 */
errno_t
strcpy_s (char *__restrict__ dest, rsize_t dmax, const char *__restrict__ src)
{
  return strcpy_s_inline (dest, dmax, src);
}

/**
 * @brief copy src string to dest string, no more than n characters
 *
 * @param *dest  pointer to string to copy to
 * @param dmax   maximum length of resulting dest string, including null
 * @param *src   pointer to string to copy from
 * @param n      maximum number of characters to copy from src, excluding null
 *
 * @constraints  No null pointers
 *               dmax shall not be zero
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *         EOVERFLOW  truncated operation. dmax - 1 characters were copied.
 *                    dest is null terminated.
 *
 */
errno_t
strncpy_s (char *__restrict__ dest, rsize_t dmax,
	   const char *__restrict__ src, rsize_t n)
{
  return strncpy_s_inline (dest, dmax, src, n);
}

/**
 * @brief append src string to dest string, including null
 *
 * @param *dest  pointer to string to append to
 * @param dmax   maximum length of resulting dest string, including null
 * @param *src   pointer to string to append from
 *
 * @constraints  No null pointers
 *               dmax shall not be zero
 *               dest shall be null terminated
 *               given m = dmax - strnlen (dest, dmax)
 *                     n = strnlen (src, m)
 *                        n shall not be >= m
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *
 */
errno_t
strcat_s (char *__restrict__ dest, rsize_t dmax, const char *__restrict__ src)
{
  return strcat_s_inline (dest, dmax, src);
}

/**
 * @brief append src string to dest string, including null, no more than n
 *        characters
 *
 * @param *dest  pointer to string to append to
 * @param dmax   maximum length of resulting dest string, including null
 * @param *src   pointer to string to append from
 * @param n      maximum characters to append (excluding null)
 *
 * @constraints  No null pointers
 *               dmax shall not be zero
 *               dest shall be null terminated
 *               dmax - strnlen (dest, dmax) shall not be zero
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *         EOVERFLOW  truncated operation. dmax - 1 characters were appended.
 *                    dest is null terminated.
 *
 */
errno_t
strncat_s (char *__restrict__ dest, rsize_t dmax,
	   const char *__restrict__ src, rsize_t n)
{
  return strncat_s_inline (dest, dmax, src, n);
}

/**
 * @brief tokenize string s1 with delimiter specified in s2. This is a stateful
 *        API when it is iterately called, it returns the next token from s1
 *        which is delimited by s2. s1max and ptr maintain the stateful
 *        information for the same caller and must not be altered by the
 *        caller during the iteration for the correct result
 *
 * @param *s1         pointer to string to be searched for substring
 * @param *s1max      restricted maximum length of s1
 * @param *s2         pointer to substring to search (16 characters max,
 *                    including null)
 * @param **ptr       in/out pointer which maintains the stateful information
 *
 * @constraints  s2, s1max, and ptr shall not be null
 *               if s1 is null, contents of ptr shall not be null
 *               s1 and s2 shall be null terminated
 *
 * @return non-null  pointer to the first character of a token
 *         s1max and ptr are modified to contain the state
 *         null      runtime constraint error or token is not found
 *
 * @example
 *   char *str2 = " ";
 *   char str1[100];
 *   uword len;
 *   char *p2str = 0;
 *   char *tok1, *tok2, *tok3, *tok4, *tok5, *tok6, *tok7;
 *
 *   strncpy (str1, "brevity is the soul of wit", sizeof (str1));
 *   len = strlen (str1);
 *   tok1 = strtok_s (str1, &len, str2, &p2str);
 *   tok2 = strtok_s (0, &len, str2, &p2str);
 *   tok3 = strtok_s (0, &len, str2, &p2str);
 *   tok4 = strtok_s (0, &len, str2, &p2str);
 *   tok5 = strtok_s (0, &len, str2, &p2str);
 *   tok6 = strtok_s (0, &len, str2, &p2str);
 *   tok7 = strtok_s (0, &len, str2, &p2str);
 *
 * After the above series of calls,
 *   tok1 = "brevity", tok2 = "is", tok3 = "the", tok4 = "soul", tok5 = "of",
 *   tok6 = "wit", tok7 = null
 */
char *
strtok_s (char *__restrict__ s1, rsize_t * __restrict__ s1max,
	  const char *__restrict__ s2, char **__restrict__ ptr)
{
  return strtok_s_inline (s1, s1max, s2, ptr);
}

/**
 * @brief compute the length in s, no more than maxsize
 *
 * @param *s      pointer to string
 * @param maxsize restricted maximum length
 *
 * @constraints   No null pointers
 *                maxsize shall not be zero
 *
 * @return size_t the string length in s, excluding null character, and no
 *                more than maxsize or 0 if there is a constraint error
 *
 */
size_t
strnlen_s (const char *s, size_t maxsize)
{
  return strnlen_s_inline (s, maxsize);
}

/**
 * @brief locate the first occurrence of the substring s2 in s1
 *
 * @param *s1         pointer to string to be searched for substring
 * @param s1max       restricted maximum length of s1
 * @param *s2         pointer to substring to search
 * @param s2max       restricted maximum length of s2
 * @param **substring pointer to pointer substring to be returned
 *
 * @constraints  No null pointers
 *               s1max and s2max shall not be zero
 *               s1 and s2 shall be null terminated
 *
 * @return EOK    success
 *         substring when the return code is EOK, it contains the pointer which
 *         points to s1 that matches s2
 *         EINVAL runtime constraint error
 *         ESRCH  no match
 *
 * @example
 *   char *sub = 0;
 *   char *s1 = "success is not final, failure is not fatal.";
 *
 *   strstr_s (s1, strlen (s1), "failure", strlen ("failure"), &sub);
 *
 * After the above call,
 *   sub = "failure is not fatal."
 */
errno_t
strstr_s (char *s1, rsize_t s1max, const char *s2, rsize_t s2max,
	  char **substring)
{
  return strstr_s_inline (s1, s1max, s2, s2max, substring);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
