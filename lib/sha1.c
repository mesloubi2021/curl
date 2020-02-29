/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Steve Holme, <steve_holme@hotmail.com>.
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

#ifndef CURL_DISABLE_CRYPTO_AUTH

#include "warnless.h"
#include "curl_sha1.h"

#ifdef USE_OPENSSL
#include <openssl/opensslconf.h>
#endif /* USE_OPENSSL */

#ifdef USE_MBEDTLS
#include <mbedtls/version.h>

#if(MBEDTLS_VERSION_NUMBER >= 0x02070000)
  #define HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS
#endif
#endif /* USE_MBEDTLS */

/* Please keep the SSL backend-specific #if branches in this order:
 *
 * 1. USE_OPENSSL
 * 2. USE_GNUTLS_NETTLE
 * 3. USE_GNUTLS
 * 4. USE_MBEDTLS
 * 5. USE_COMMON_CRYPTO
 * 6. USE_WIN32_CRYPTO
 *
 * This ensures that the same SSL branch gets activated throughout this source
 * file even if multiple backends are enabled at the same time.
 */

#if (defined(USE_OPENSSL) && !defined(OPENSSL_NO_SHA1))

/* When OpenSSL is available we use the SHA1-function from OpenSSL */
#include <openssl/sha.h>

#elif defined(USE_GNUTLS_NETTLE)

#include <nettle/sha.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef struct sha1_ctx SHA_CTX;

static void SHA1_Init(SHA_CTX *ctx)
{
  sha1_init(ctx);
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *data,
                        unsigned int length)
{
  sha1_update(ctx, length, data);
}

static void SHA1_Final(unsigned char *digest, SHA_CTX *ctx)
{
  sha1_digest(ctx, SHA1_DIGEST_SIZE, digest);
}

#elif defined(USE_GNUTLS)

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef struct gcry_md_hd_t SHA_CTX;

static int SHA1_Init(SHA_CTX *ctx)
{
  gcry_md_open(ctx, GCRY_MD_SHA1, 0);
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *input,
                        unsigned int length)
{
  gcry_md_write(*ctx, input, length);
}

static void SHA1_Final(unsigned char *digest, SHA_CTX *ctx)
{
  memcpy(digest, gcry_md_read(*ctx, 0), SHA1_DIGEST_LENGTH);
  gcry_md_close(*ctx);
}

#elif defined(USE_MBEDTLS)

#include <mbedtls/sha1.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef mbedtls_sha1_context SHA_CTX;

static void SHA1_Init(SHA_CTX *ctx)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  mbedtls_sha1_starts(ctx);
#else
  (void) mbedtls_sha1_starts_ret(ctx);
#endif
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *data,
                        unsigned int length)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  mbedtls_sha1_update(ctx, data, length);
#else
  (void) mbedtls_sha1_update_ret(ctx, data, length);
#endif
}

static void SHA1_Final(unsigned char *digest, SHA_CTX *ctx)
{
#if !defined(HAS_MBEDTLS_RESULT_CODE_BASED_FUNCTIONS)
  mbedtls_sha1_finish(ctx, digest);
#else
  (void) mbedtls_sha1_finish_ret(ctx, digest);
#endif
}

#elif (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
              (__MAC_OS_X_VERSION_MAX_ALLOWED >= 1040)) || \
      (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
              (__IPHONE_OS_VERSION_MAX_ALLOWED >= 20000))

#include <CommonCrypto/CommonDigest.h>

#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

typedef CC_SHA1_CTX SHA_CTX;

static void SHA1_Init(SHA_CTX *ctx)
{
  (void) CC_SHA1_Init(ctx);
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *data,
                        unsigned int length)
{
  (void) CC_SHA1_Update(ctx, data, length);
}

static void SHA1_Final(unsigned char *digest, SHA_CTX *ctx)
{
  (void) CC_SHA1_Final(digest, ctx);
}

#elif defined(USE_WIN32_CRYPTO)

#include <wincrypt.h>

typedef struct {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
} SHA_CTX;

static void SHA1_Init(SHA_CTX *ctx)
{
  if(CryptAcquireContext(&ctx->hCryptProv, NULL, NULL,
                         PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    CryptCreateHash(ctx->hCryptProv, CALG_SHA1, 0, 0, &ctx->hHash);
  }
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *data,
                        unsigned int length)
{
  CryptHashData(ctx->hHash, (unsigned char *) data, length, 0);
}

static void SHA1_Final(unsigned char *digest, SHA_CTX *ctx)
{
  unsigned long length;

  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == SHA1_DIGEST_LENGTH)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);

  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);

  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#else

#error "Cannot compile SHA1 support without a crypto library."

#endif

void Curl_sha1it(unsigned char *output, const unsigned char *input)
{
  SHA_CTX ctx;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, input, curlx_uztoui(strlen((char *) input)));
  SHA1_Final(output, &ctx);
}

#endif /* CURL_DISABLE_CRYPTO_AUTH */
