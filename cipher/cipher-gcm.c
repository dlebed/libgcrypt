/* cipher-gcm.c  - Generic Galois Counter Mode implementation
 * Copyright (C) 2013 Dmitry Eremin-Solenikov
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "ath.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

void dump(const unsigned char *d)
{
  int i;
  for (i = 0; i < 16 ; i++)
    printf("%02x ", d[i]);
  printf("\n");
}
void dumpl(const unsigned long *d)
{
  int i;
  for (i = 0; i < 4 ; i++)
    printf("%08lx ", d[i]);
  printf("\n");
}
#if 0
static unsigned bshift(unsigned char *b)
{
  unsigned char c;
  int i;
  c = b[15] & 1;
  for (i = 15; i > 0; i--)
    {
      b[i] = (b[i] >> 1) | (b[i-1] << 7);
    }
  b[i] >>= 1;
  return c;
}

static void ghash(unsigned char *hsub, unsigned char *result, const unsigned char *buf)
{
  unsigned char V[16];
  int i, j;

  buf_xor(V, result, buf, 16);

  memset(result, 0, 16);

  for (i = 0; i < 16; i++)
    {
      for (j = 0x80; j ; j >>= 1)
        {
          if (hsub[i] & j)
            buf_xor(result, result, V, 16);
          if (bshift(V))
            V[0] ^= 0xe1;
        }
    }
}
#else
static unsigned long bshift(unsigned long *b)
{
  unsigned long c;
  int i;
  c = b[3] & 1;
  for (i = 3; i > 0; i--)
    {
      b[i] = (b[i] >> 1) | (b[i-1] << 31);
    }
  b[i] >>= 1;
  return c;
}

static void ghash(unsigned char *hsub, unsigned char *result, const unsigned char *buf)
{
  unsigned long V[4];
  int i, j;
  byte *p;

#ifdef WORDS_BIGENDIAN
  p = result;
#else
  unsigned long T[4];

  buf_xor(V, result, buf, 16);
  for (i = 0; i < 4; i++)
    {
      V[i] = (V[i] & 0x00ff00ff) << 8 |
             (V[i] & 0xff00ff00) >> 8;
      V[i] = (V[i] & 0x0000ffff) << 16 |
             (V[i] & 0xffff0000) >> 16;
    }
  p = (byte *) T;
#endif

  memset(p, 0, 16);

  for (i = 0; i < 16; i++)
    {
      for (j = 0x80; j ; j >>= 1)
        {
          if (hsub[i] & j)
            buf_xor(p, p, V, 16);
          if (bshift(V))
            V[0] ^= 0xe1000000;
        }
    }
#ifndef WORDS_BIGENDIAN
  for (i = 0, p = (byte *) T; i < 16; i += 4, p += 4)
    {
      result[i + 0] = p[3];
      result[i + 1] = p[2];
      result[i + 2] = p[1];
      result[i + 3] = p[0];
    }
#endif
}
#endif


gcry_err_code_t
_gcry_cipher_gcm_encrypt (gcry_cipher_hd_t c,
                          byte *outbuf, unsigned int outbuflen,
                          const byte *inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->cipher->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset(tmp, 0, 16);
      _gcry_cipher_gcm_setiv(c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i-1]++;
          if (c->u_ctr.ctr[i-1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;

      i = blocksize - 1;
      c->length[i] += n * 8;
      for ( ; c->length[i] == 0 && i > blocksize / 2; i --)
        c->length[i - 1]++;

      c->cipher->encrypt (&c->context.c, tmp, c->u_ctr.ctr);
      if (n < blocksize)
        {
          buf_xor_2dst (outbuf, tmp, inbuf, n);
          memset(tmp + n, 0, blocksize - n);
          ghash (c->u_iv.iv, c->u_tag.tag, tmp);
        } else {
          buf_xor (outbuf, tmp, inbuf, n);
          ghash (c->u_iv.iv, c->u_tag.tag, outbuf);
        }

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_decrypt (gcry_cipher_hd_t c,
                          byte *outbuf, unsigned int outbuflen,
                          const byte *inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->cipher->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset(tmp, 0, 16);
      _gcry_cipher_gcm_setiv(c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i-1]++;
          if (c->u_ctr.ctr[i-1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;
      if (n < blocksize)
        {
          memcpy (tmp, inbuf, n);
          memset(tmp + n, 0, blocksize - n);
          ghash (c->u_iv.iv, c->u_tag.tag, tmp);
        } else {
          ghash (c->u_iv.iv, c->u_tag.tag, inbuf);
        }

      i = blocksize - 1;
      c->length[i] += n * 8;
      for ( ; c->length[i] == 0 && i > blocksize / 2; i --)
        c->length[i - 1]++;

      c->cipher->encrypt (&c->context.c, tmp, c->u_ctr.ctr);

      buf_xor (outbuf, inbuf, tmp, n);

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_authenticate (gcry_cipher_hd_t c,
                               const byte *aadbuf, unsigned int aadbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->cipher->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (!c->marks.iv)
    {
      memset(tmp, 0, 16);
      _gcry_cipher_gcm_setiv(c, tmp, 16);
    }

  n = aadbuflen;
  i = blocksize / 2;
  c->length[i-1] = (n % 0x20) * 8;
  n /= 0x20;
  for (; n && i > 0; i--, n >>= 8)
    c->length[i-1] = n & 0xff;

  while (aadbuflen >= blocksize)
    {
      ghash (c->u_iv.iv, c->u_tag.tag, aadbuf);

      aadbuflen -= blocksize;
      aadbuf += blocksize;
   }

  if (aadbuflen != 0)
    {
      memcpy(tmp, aadbuf, aadbuflen);
      memset(tmp + aadbuflen, 0, blocksize - aadbuflen);

      ghash (c->u_iv.iv, c->u_tag.tag, tmp);
    }

  return 0;
}

void
_gcry_cipher_gcm_setiv (gcry_cipher_hd_t c,
                        const byte *iv, unsigned int ivlen)
{
  memset (c->length, 0, 16);
  memset (c->u_tag.tag, 0, 16);
  c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_tag.tag );

  if (ivlen != 16 - 4)
    {
      unsigned char tmp[MAX_BLOCKSIZE];
      unsigned n;
      memset(c->u_ctr.ctr, 0, 16);
      for (n = ivlen; n >= 16; n -= 16, iv += 16)
        ghash (c->u_iv.iv, c->u_ctr.ctr, iv);
      if (n != 0)
        {
          memcpy(tmp, iv, n);
          memset(tmp + n, 0, 16 - n);
          ghash (c->u_iv.iv, c->u_ctr.ctr, tmp);
        }
      memset(tmp, 0, 16);
      n = 16;
      tmp[n-1] = (ivlen % 0x20) * 8;
      ivlen /= 0x20;
      n--;
      for (; n > 0; n--, ivlen >>= 8)
        tmp[n-1] = ivlen & 0xff;
      ghash (c->u_iv.iv, c->u_ctr.ctr, tmp);
    } else {
      memcpy (c->u_ctr.ctr, iv, ivlen);
      c->u_ctr.ctr[12] = c->u_ctr.ctr[13] = c->u_ctr.ctr[14] = 0;
      c->u_ctr.ctr[15] = 1;
    }

  c->cipher->encrypt ( &c->context.c, c->lastiv, c->u_ctr.ctr );
  c->marks.iv = 1;

}

gcry_err_code_t
_gcry_cipher_gcm_tag (gcry_cipher_hd_t c,
                      byte *outbuf, unsigned int outbuflen)
{
  if (outbuflen < 16)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.tag)
    {
      ghash (c->u_iv.iv, c->u_tag.tag, c->length);
      buf_xor (c->u_tag.tag, c->lastiv, c->u_tag.tag, 16);
      c->marks.tag = 1;
    }
  memcpy (outbuf, c->u_tag.tag, 16);

  return 0;
}
