/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * NTLM details:
 *
 * https://davenport.sourceforge.io/ntlm.html
 * https://www.innovation.ch/java/ntlm.html
 */

/* Please keep the SSL backend-specific #if branches in this order:

   1. USE_OPENSSL
   2. USE_GNUTLS_NETTLE
   3. USE_GNUTLS
   4. USE_NSS
   5. USE_MBEDTLS
   6. USE_SECTRANSP
   7. USE_OS400CRYPTO
   8. USE_WIN32_CRYPTO

   This ensures that:
   - the same SSL branch gets activated throughout this source
     file even if multiple backends are enabled at the same time.
   - OpenSSL and NSS have higher priority than Windows Crypt, due
     to issues with the latter supporting NTLM2Session responses
     in NTLM type-3 messages.
 */

#if !defined(USE_WINDOWS_SSPI) || defined(USE_WIN32_CRYPTO)

#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE) || \
    defined(USE_GNUTLS) || defined(USE_NSS) || defined(USE_MBEDTLS) || \
    defined(USE_SECTRANSP) || defined(USE_OS400CRYPTO)

/* Nothing - Now in curl_des.c */

#elif defined(USE_WIN32_CRYPTO)
#  include <wincrypt.h>
#else
#  error "Can't compile NTLM support without a crypto library."
#endif

#include "urldata.h"
#include "non-ascii.h"
#include "strcase.h"
#include "curl_ntlm_core.h"
#include "curl_md5.h"
#include "curl_hmac.h"
#include "warnless.h"
#include "curl_endian.h"
#include "curl_des.h"
#include "curl_md4.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define NTLMv2_BLOB_SIGNATURE "\x01\x01\x00\x00"
#define NTLMv2_BLOB_LEN       (44 -16 + ntlm->target_info_len + 4)

#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE) || \
    defined(USE_GNUTLS) || defined(USE_NSS) || defined(USE_MBEDTLS) || \
    defined(USE_SECTRANSP) || defined(USE_OS400CRYPTO)

/* Nothing - Now in curl_des.c */

#elif defined(USE_WIN32_CRYPTO)

static bool encrypt_des(const unsigned char *in, unsigned char *out,
                        const unsigned char *key_56)
{
  HCRYPTPROV hprov;
  HCRYPTKEY hkey;
  struct {
    BLOBHEADER hdr;
    unsigned int len;
    char key[8];
  } blob;
  DWORD len = 8;

  /* Acquire the crypto provider */
  if(!CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT))
    return FALSE;

  /* Setup the key blob structure */
  memset(&blob, 0, sizeof(blob));
  blob.hdr.bType = PLAINTEXTKEYBLOB;
  blob.hdr.bVersion = 2;
  blob.hdr.aiKeyAlg = CALG_DES;
  blob.len = sizeof(blob.key);

  /* Expand the 56-bit key to 64-bits */
  Curl_extend_key_56_to_64(key_56, blob.key);

  /* Set the key parity to odd */
  Curl_des_set_odd_parity((unsigned char *) blob.key, sizeof(blob.key));

  /* Import the key */
  if(!CryptImportKey(hprov, (BYTE *) &blob, sizeof(blob), 0, 0, &hkey)) {
    CryptReleaseContext(hprov, 0);

    return FALSE;
  }

  memcpy(out, in, 8);

  /* Perform the encryption */
  CryptEncrypt(hkey, 0, FALSE, 0, out, &len, len);

  CryptDestroyKey(hkey);
  CryptReleaseContext(hprov, 0);

  return TRUE;
}

#endif /* defined(USE_WIN32_CRYPTO) */

 /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */
void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                            const unsigned char *plaintext,
                            unsigned char *results)
{
#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE) || \
    defined(USE_GNUTLS) || defined(USE_NSS) || defined(USE_MBEDTLS) || \
    defined(USE_SECTRANSP) || defined(USE_OS400CRYPTO)

  Curl_3desit(keys, plaintext, results);

#elif defined(USE_WIN32_CRYPTO)
  encrypt_des(plaintext, results, keys);
  encrypt_des(plaintext, results + 8, keys + 7);
  encrypt_des(plaintext, results + 16, keys + 14);
#endif
}

/*
 * Set up lanmanager hashed password
 */
CURLcode Curl_ntlm_core_mk_lm_hash(struct Curl_easy *data,
                                   const char *password,
                                   unsigned char *lmbuffer /* 21 bytes */)
{
  CURLcode result;
  unsigned char pw[14];
  static const unsigned char magic[] = {
    0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 /* i.e. KGS!@#$% */
  };
  size_t len = CURLMIN(strlen(password), 14);

  Curl_strntoupper((char *)pw, password, len);
  memset(&pw[len], 0, 14 - len);

  /*
   * The LanManager hashed password needs to be created using the
   * password in the network encoding not the host encoding.
   */
  result = Curl_convert_to_network(data, (char *)pw, 14);
  if(result)
    return result;

  {
    /* Create LanManager hashed password. */

#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE) || \
    defined(USE_GNUTLS) || defined(USE_NSS) || defined(USE_MBEDTLS) || \
    defined(USE_SECTRANSP) || defined(USE_OS400CRYPTO)

    Curl_2desit(pw, magic, lmbuffer);

#elif defined(USE_WIN32_CRYPTO)
    encrypt_des(magic, lmbuffer, pw);
    encrypt_des(magic, lmbuffer + 8, pw + 7);
#endif

    memset(lmbuffer + 16, 0, 21 - 16);
  }

  return CURLE_OK;
}

#ifdef USE_NTRESPONSES
static void ascii_to_unicode_le(unsigned char *dest, const char *src,
                                size_t srclen)
{
  size_t i;
  for(i = 0; i < srclen; i++) {
    dest[2 * i] = (unsigned char)src[i];
    dest[2 * i + 1] = '\0';
  }
}

#if defined(USE_NTLM_V2) && !defined(USE_WINDOWS_SSPI)

static void ascii_uppercase_to_unicode_le(unsigned char *dest,
                                          const char *src, size_t srclen)
{
  size_t i;
  for(i = 0; i < srclen; i++) {
    dest[2 * i] = (unsigned char)(Curl_raw_toupper(src[i]));
    dest[2 * i + 1] = '\0';
  }
}

#endif /* USE_NTLM_V2 && !USE_WINDOWS_SSPI */

/*
 * Set up nt hashed passwords
 * @unittest: 1600
 */
CURLcode Curl_ntlm_core_mk_nt_hash(struct Curl_easy *data,
                                   const char *password,
                                   unsigned char *ntbuffer /* 21 bytes */)
{
  size_t len = strlen(password);
  unsigned char *pw;
  CURLcode result;
  if(len > SIZE_T_MAX/2) /* avoid integer overflow */
    return CURLE_OUT_OF_MEMORY;
  pw = len ? malloc(len * 2) : (unsigned char *)strdup("");
  if(!pw)
    return CURLE_OUT_OF_MEMORY;

  ascii_to_unicode_le(pw, password, len);

  /*
   * The NT hashed password needs to be created using the password in the
   * network encoding not the host encoding.
   */
  result = Curl_convert_to_network(data, (char *)pw, len * 2);
  if(result)
    return result;

  /* Create NT hashed password. */
  Curl_md4it(ntbuffer, pw, 2 * len);

  memset(ntbuffer + 16, 0, 21 - 16);

  free(pw);

  return CURLE_OK;
}

#if defined(USE_NTLM_V2) && !defined(USE_WINDOWS_SSPI)

/* This creates the NTLMv2 hash by using NTLM hash as the key and Unicode
 * (uppercase UserName + Domain) as the data
 */
CURLcode Curl_ntlm_core_mk_ntlmv2_hash(const char *user, size_t userlen,
                                       const char *domain, size_t domlen,
                                       unsigned char *ntlmhash,
                                       unsigned char *ntlmv2hash)
{
  /* Unicode representation */
  size_t identity_len;
  unsigned char *identity;
  CURLcode result = CURLE_OK;

  /* we do the length checks below separately to avoid integer overflow risk
     on extreme data lengths */
  if((userlen > SIZE_T_MAX/2) ||
     (domlen > SIZE_T_MAX/2) ||
     ((userlen + domlen) > SIZE_T_MAX/2))
    return CURLE_OUT_OF_MEMORY;

  identity_len = (userlen + domlen) * 2;
  identity = malloc(identity_len);

  if(!identity)
    return CURLE_OUT_OF_MEMORY;

  ascii_uppercase_to_unicode_le(identity, user, userlen);
  ascii_to_unicode_le(identity + (userlen << 1), domain, domlen);

  result = Curl_hmacit(Curl_HMAC_MD5, ntlmhash, 16, identity, identity_len,
                       ntlmv2hash);
  free(identity);

  return result;
}

/*
 * Curl_ntlm_core_mk_ntlmv2_resp()
 *
 * This creates the NTLMv2 response as set in the ntlm type-3 message.
 *
 * Parameters:
 *
 * ntlmv2hash       [in] - The ntlmv2 hash (16 bytes)
 * challenge_client [in] - The client nonce (8 bytes)
 * ntlm             [in] - The ntlm data struct being used to read TargetInfo
                           and Server challenge received in the type-2 message
 * ntresp          [out] - The address where a pointer to newly allocated
 *                         memory holding the NTLMv2 response.
 * ntresp_len      [out] - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_ntlm_core_mk_ntlmv2_resp(unsigned char *ntlmv2hash,
                                       unsigned char *challenge_client,
                                       struct ntlmdata *ntlm,
                                       unsigned char **ntresp,
                                       unsigned int *ntresp_len)
{
/* NTLMv2 response structure :
------------------------------------------------------------------------------
0     HMAC MD5         16 bytes
------BLOB--------------------------------------------------------------------
16    Signature        0x01010000
20    Reserved         long (0x00000000)
24    Timestamp        LE, 64-bit signed value representing the number of
                       tenths of a microsecond since January 1, 1601.
32    Client Nonce     8 bytes
40    Unknown          4 bytes
44    Target Info      N bytes (from the type-2 message)
44+N  Unknown          4 bytes
------------------------------------------------------------------------------
*/

  unsigned int len = 0;
  unsigned char *ptr = NULL;
  unsigned char hmac_output[HMAC_MD5_LENGTH];
  curl_off_t tw;

  CURLcode result = CURLE_OK;

#if CURL_SIZEOF_CURL_OFF_T < 8
#error "this section needs 64bit support to work"
#endif

  /* Calculate the timestamp */
#ifdef DEBUGBUILD
  char *force_timestamp = getenv("CURL_FORCETIME");
  if(force_timestamp)
    tw = CURL_OFF_T_C(11644473600) * 10000000;
  else
#endif
    tw = ((curl_off_t)time(NULL) + CURL_OFF_T_C(11644473600)) * 10000000;

  /* Calculate the response len */
  len = HMAC_MD5_LENGTH + NTLMv2_BLOB_LEN;

  /* Allocate the response */
  ptr = calloc(1, len);
  if(!ptr)
    return CURLE_OUT_OF_MEMORY;

  /* Create the BLOB structure */
  msnprintf((char *)ptr + HMAC_MD5_LENGTH, NTLMv2_BLOB_LEN,
            "%c%c%c%c"   /* NTLMv2_BLOB_SIGNATURE */
            "%c%c%c%c",  /* Reserved = 0 */
            NTLMv2_BLOB_SIGNATURE[0], NTLMv2_BLOB_SIGNATURE[1],
            NTLMv2_BLOB_SIGNATURE[2], NTLMv2_BLOB_SIGNATURE[3],
            0, 0, 0, 0);

  Curl_write64_le(tw, ptr + 24);
  memcpy(ptr + 32, challenge_client, 8);
  memcpy(ptr + 44, ntlm->target_info, ntlm->target_info_len);

  /* Concatenate the Type 2 challenge with the BLOB and do HMAC MD5 */
  memcpy(ptr + 8, &ntlm->nonce[0], 8);
  result = Curl_hmacit(Curl_HMAC_MD5, ntlmv2hash, HMAC_MD5_LENGTH, ptr + 8,
                    NTLMv2_BLOB_LEN + 8, hmac_output);
  if(result) {
    free(ptr);
    return result;
  }

  /* Concatenate the HMAC MD5 output  with the BLOB */
  memcpy(ptr, hmac_output, HMAC_MD5_LENGTH);

  /* Return the response */
  *ntresp = ptr;
  *ntresp_len = len;

  return result;
}

/*
 * Curl_ntlm_core_mk_lmv2_resp()
 *
 * This creates the LMv2 response as used in the ntlm type-3 message.
 *
 * Parameters:
 *
 * ntlmv2hash        [in] - The ntlmv2 hash (16 bytes)
 * challenge_client  [in] - The client nonce (8 bytes)
 * challenge_client  [in] - The server challenge (8 bytes)
 * lmresp           [out] - The LMv2 response (24 bytes)
 *
 * Returns CURLE_OK on success.
 */
CURLcode  Curl_ntlm_core_mk_lmv2_resp(unsigned char *ntlmv2hash,
                                      unsigned char *challenge_client,
                                      unsigned char *challenge_server,
                                      unsigned char *lmresp)
{
  unsigned char data[16];
  unsigned char hmac_output[16];
  CURLcode result = CURLE_OK;

  memcpy(&data[0], challenge_server, 8);
  memcpy(&data[8], challenge_client, 8);

  result = Curl_hmacit(Curl_HMAC_MD5, ntlmv2hash, 16, &data[0], 16,
                       hmac_output);
  if(result)
    return result;

  /* Concatenate the HMAC MD5 output  with the client nonce */
  memcpy(lmresp, hmac_output, 16);
  memcpy(lmresp + 16, challenge_client, 8);

  return result;
}

#endif /* USE_NTLM_V2 && !USE_WINDOWS_SSPI */

#endif /* USE_NTRESPONSES */

#endif /* !USE_WINDOWS_SSPI || USE_WIN32_CRYPTO */

#endif /* USE_NTLM */
