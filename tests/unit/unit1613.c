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
#include "curlcheck.h"

#include "curl_sha1.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START

#ifndef CURL_DISABLE_CRYPTO_AUTH
  const char string1[] = "1";
  const char string2[] = "hello-you-fool";
  unsigned char output[SHA1_DIGEST_LENGTH];
  unsigned char *testp = output;

  Curl_sha1it(output, (const unsigned char *) string1, strlen(string1));

  verify_memory(testp,
                "\x35\x6a\x19\x2b\x79\x13\xb0\x4c\x54\x57\x4d\x18\xc2\x8d\x46"
                "\xe6\x39\x54\x28\xab", SHA1_DIGEST_LENGTH);

  Curl_sha1it(output, (const unsigned char *) string2, strlen(string2));

  verify_memory(testp,
                "\xda\x9c\xb0\x03\xc5\x2e\x7e\xc3\x44\x76\xb2\xcd\x0a\x36\x3c"
                "\x2d\xed\x7b\x0a\x89", SHA1_DIGEST_LENGTH);
#endif


UNITTEST_STOP
