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
#include "curlcheck.h"

#include "curl_des.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START

#ifndef CURL_DISABLE_CRYPTO_AUTH
  const char password[] = "Pa55worDPa55worDPa55worD";
  const char string1[] = "1\x00\x00\x00\x00\x00\x00\x00";
  const char string2[] = "hello-you-fool";
  unsigned char output[100];
  unsigned char *testp = output;

  Curl_desit((const unsigned char *) password,
             (const unsigned char *) string1,
             output);

  verify_memory(testp,
                "\xD6\xF1\x39\xF3\x19\x43\x70\x00",
                8);

  Curl_desit((const unsigned char *) password,
             (const unsigned char *) string2,
             output);

  verify_memory(testp,
                "\x88\x66\x5C\xF5\x03\xE8\x44\xD2\x5D\xF1\x90\xA0\x16\xAB\x37"
                "\xB0",
                16);
#endif


UNITTEST_STOP
