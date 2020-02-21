/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2015 - 2020, Steve Holme, <steve_holme@hotmail.com>.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_NTLM)

#include "curl_des.h"

#define DES_KEY_SIZE 8

#if defined(USE_OPENSSL)

#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#if (OPENSSL_VERSION_NUMBER < 0x00907001L)
#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_odd_parity des_set_odd_parity
#define DES_set_key des_set_key
#define DES_ecb_encrypt des_ecb_encrypt
#define DESKEY(x) *x
#else
#define DESKEY(x) x
#endif

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef DES_key_schedule DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  DES_cblock key;

  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, (char *) &key);

  /* Set the key parity to odd */
  DES_set_odd_parity(&key);

  /* Set the key */
  DES_set_key(&key, ctx);
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  DES_ecb_encrypt((DES_cblock *) input, (DES_cblock *) output, DESKEY(ctx),
                  DES_ENCRYPT);
}

static void DES_Final(DES_CTX *ctx)
{
  /* Nothing to do when using OpenSSL */
  (void) ctx;
}

#elif defined(USE_GNUTLS_NETTLE)

#include <nettle/des.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef des_ctx DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  char key[DES_KEY_SIZE];

  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, key);

  /* Set the key parity to odd */
  Curl_des_set_odd_parity((unsigned char *) key, sizeof(key));

  /* Set the key */
  des_set_key(des, (const uint8_t *) key);
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  des_encrypt(&ctx, DES_KEY_SIZE, output, input);
}

static void DES_Final(DES_CTX *ctx)
{
  /* Nothing to do when using GNU TLS Nettle */
  (void) ctx;
}

#el if defined(USE_GNUTLS)

#include <gcrypt.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef gcry_cipher_hd_t DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  char key[DES_KEY_SIZE];

  /* Open the cipher */
  gcry_cipher_open(ctx, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);

  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, key);

  /* Set the key parity to odd */
  Curl_des_set_odd_parity((unsigned char *) key, sizeof(key));

  /* Set the key */
  gcry_cipher_setkey(*ctx, key, sizeof(key));
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  gcry_cipher_encrypt(*ctx, results, DES_KEY_SIZE, input, DES_KEY_SIZE);
}

static void DES_Final(DES_CTX *ctx)
{
  gcry_cipher_close(*ctx);
}

#elif defined(USE_NSS)

#include <nss.h>
#include <pk11pub.h>
#include <hasht.h>

include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef struct {
  PK11SlotInfo *slot;
  PK11SymKey *symkey;
  SECItem *param;

  PK11Context *ctx;   /* The actual encryption context */
  unsigned int len;
} DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  const CK_MECHANISM_TYPE mech = CKM_DES_ECB; /* DES cipher in ECB mode */

  /* Initialise the context */
  memset(ctx, 0, sizeof(DES_CTX));

  /* Use an internal slot for DES encryption */
  ctx->slot = PK11_GetInternalKeySlot();
  if(ctx->slot) {
    char key[DES_KEY_SIZE];
    SECItem key_item;

    /* Expand the 56-bit key to 64-bits */
    Curl_extend_key_56_to_64(key_56, key);

    /* Set the key parity to odd */
    Curl_des_set_odd_parity((unsigned char *) key, sizeof(key));

    /* Import the key */
    key_item.data = (unsigned char *) key;
    key_item.len = sizeof(key);
    ctx->symkey = PK11_ImportSymKey(ctx->slot, mech, PK11_OriginUnwrap,
                                    CKA_ENCRYPT, &key_item, NULL);
    if(ctx->symkey) {
      ctx->param = PK11_ParamFromIV(mech, /* no IV in ECB mode */ NULL);
      if(ctx->param)
        /* Create the DES encryption context */
        ctx->ctx = PK11_CreateContextBySymKey(mech, CKA_ENCRYPT, ctx->symkey,
                                              param);
    }
  }
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  if(ctx->ctx) {
    int len;

    /* Perform the encryption */
    if(!PK11_CipherOp(ctx->ctx, output, &len, DES_KEY_SIZE,
                      (unsigned char *) input, DES_KEY_SIZE))
      /* Success */
      ctx->len = len;
  }
}

static void DES_Final(DES_CTX *ctx)
{
  /* Finalise to shutdown the sessions */
  if(ctx->len) {
    PK11_Finalize(ctx->ctx);
    ctx->len = 0;
  }

  /* Destroy the encryption context */
  if(ctx->ctx) {
    PK11_DestroyContext(ctx->ctx, PR_TRUE);
    ctx->ctx = NULL;
  }

  /* Free the symmetric key */
  if(ctx->symkey) {
    PK11_FreeSymKey(ctx->symkey);
    ctx->symkey = NULL;
  }

  /* Free the mechanism parameter */
  if(ctx->param) {
    SECITEM_FreeItem(param, PR_TRUE);
    ctx->param = NULL;
  }

  /* Free the internal PK11 slot */
  if(ctx->slot) {
    PK11_FreeSlot(ctx->slot);
    ctx->slot = NULL;
  }
}

#elif defined(USE_MBEDTLS)

#include <mbedtls/des.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef mbedtls_des_context DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  char key[DES_KEY_SIZE];

  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, key);

  /* Set the key parity to odd */
  mbedtls_des_key_set_parity((unsigned char *) key);

  /* Set the key */
  mbedtls_des_init(ctx);
  mbedtls_des_setkey_enc(ctx, (unsigned char *) key);
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  (void) mbedtls_des_crypt_ecb(ctx, input, output);
}

static void DES_Final(DES_CTX *ctx)
{
  /* Nothing to do when using mbed TLS */
  (void) ctx;
}

#elif defined(USE_SECTRANSP)

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

typedef struct {
  char key[DES_KEY_SIZE];
} DES_CTX;

static void DES_Init(DES_CTX *ctx, const unsigned char *key_56)
{
  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, ctx->key);

  /* Set the key parity to odd */
  Curl_des_set_odd_parity((unsigned char *) ctx->key, sizeof(ctx->key));
}

static void DES_Encrypt(DES_CTX *ctx,
                        const unsigned char *input,
                        unsigned char *output)
{
  size_t len;

  CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, ctx->key,
          kCCKeySizeDES, NULL, in, DES_KEY_SIZE, out, DES_KEY_SIZE, &len);
}

static void DES_Final(DES_CTX *ctx)
{
  /* Nothing to do when using the Secure Transport crypto library */
  (void) ctx;
}

#endif

/*
 * Curl_extend_key_56_to_64()
 *
 * Turns a 56-bit key into being 64-bit wide.
 *
 * Parameters:
 *
 * key_56 [in]     - The 56-bit input key.
 * key    [in/out] - The 64-bit output.
 */
void Curl_extend_key_56_to_64(const unsigned char *key_56, char *key)
{
  key[0] = key_56[0];
  key[1] = (unsigned char) (((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
  key[2] = (unsigned char) (((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
  key[3] = (unsigned char) (((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
  key[4] = (unsigned char) (((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
  key[5] = (unsigned char) (((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
  key[6] = (unsigned char) (((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
  key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);
}

#if !defined(USE_OPENSSL) && !defined(USE_MBEDTLS)

/*
 * Curl_des_set_odd_parity()
 *
 * This is used to apply odd parity to the given byte array. It is typically
 * used by when a cryptography engines doesn't have it's own version.
 *
 * The function is a port of the Java based oddParity() function over at:
 *
 * https://davenport.sourceforge.io/ntlm.html
 *
 * Parameters:
 *
 * bytes       [in/out] - The data whose parity bits are to be adjusted for
 *                        odd parity.
 * len         [out]    - The length of the data.
 */
void Curl_des_set_odd_parity(unsigned char *bytes, size_t len)
{
  size_t i;

  for(i = 0; i < len; i++) {
    unsigned char b = bytes[i];

    bool needs_parity = (((b >> 7) ^ (b >> 6) ^ (b >> 5) ^
                          (b >> 4) ^ (b >> 3) ^ (b >> 2) ^
                          (b >> 1)) & 0x01) == 0;

    if(needs_parity)
      bytes[i] |= 0x01;
    else
      bytes[i] &= 0xfe;
  }
}

#endif /* !defined(USE_OPENSSL) && !defined(USE_MBEDTLS) */

#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE) || \
    defined(USE_GNUTLS) || defined(USE_NSS) || defined(USE_MBEDTLS) || \
    defined(USE_SECTRANSP)

/*
 * Curl_2desit()
 *
 * Performs the 2DES encryption.
 *
 * Parameters:
 *
 * key    [in]     - The key.
 * input  [in]     - The input data.
 * output [in/out] - The output buffer.
 */
void Curl_2desit(const unsigned char *key,
                 const unsigned char *input,
                 unsigned char *output)
{
  DES_CTX ctx;

  DES_Init(&ctx, key);
  DES_Encrypt(&ctx, input, output);
  DES_Final(&ctx);

  DES_Init(&ctx, key + 7);
  DES_Encrypt(&ctx, input, output + 8);
  DES_Final(&ctx);
}

/*
 * Curl_3desit()
 *
 * Performs the 3DES encryption.
 *
 * Parameters:
 *
 * key    [in]     - The key.
 * input  [in]     - The input data.
 * output [in/out] - The output buffer.
 */
void Curl_3desit(const unsigned char *key,
                 const unsigned char *input,
                 unsigned char *output)
{
  DES_CTX ctx;

  DES_Init(&ctx, key);
  DES_Encrypt(&ctx, input, output);
  DES_Final(&ctx);

  DES_Init(&ctx, key + 7);
  DES_Encrypt(&ctx, input, output + 8);
  DES_Final(&ctx);

  DES_Init(&ctx, key + 14);
  DES_Encrypt(&ctx, input, output + 16);
  DES_Final(&ctx);
}

#endif

#endif /* USE_NTLM */
