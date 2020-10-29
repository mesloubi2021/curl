#ifndef HEADER_CURL_SYSTEM_DURANGO_H
#define HEADER_CURL_SYSTEM_DURANGO_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2016 - 2020, Steve Holme, <steve_holme@hotmail.com>.
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

#if defined(DURANGO)

extern LARGE_INTEGER Curl_freq;
extern bool Curl_isVistaOrGreater;

CURLcode Curl_durango_init(long flags);
void Curl_durango_cleanup(long init_flags);

/* We use our own typedef here since some headers might lack this */
typedef unsigned int(WINAPI *IF_NAMETOINDEX_FN)(const char *);

/* This is used instead of if_nametoindex if available on Windows */
extern IF_NAMETOINDEX_FN Curl_if_nametoindex;

#endif /* DURANGO */

#endif /* HEADER_CURL_SYSTEM_DURANGO_H */
