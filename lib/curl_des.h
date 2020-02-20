#ifndef HEADER_CURL_DES_H
#define HEADER_CURL_DES_H
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

#define DES_KEY_LENGTH 32

void Curl_extend_key_56_to_64(const unsigned char *key_56, char *key);

#if !defined(USE_OPENSSL)
void Curl_des_set_odd_parity(unsigned char *bytes, size_t length);
#endif

#if defined(USE_OPENSSL) || defined(USE_GNUTLS_NETTLE)
void Curl_2desit(const unsigned char *key, const unsigned char *input,
                 unsigned char *output);
void Curl_3desit(const unsigned char *key, const unsigned char *input,
                 unsigned char *output);
#endif

#endif /* USE_NTLM */

#endif /* HEADER_CURL_DES_H */
