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

#include <curl/curl.h>
#include "system_durango.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

LARGE_INTEGER Curl_freq;
bool Curl_isVistaOrGreater = TRUE;

/* Curl_win32_init() performs win32 global initialization */
CURLcode Curl_durango_init(long flags)
{
  /* CURL_GLOBAL_WIN32 controls the *optional* part of the initialization which
     is just for Winsock at the moment. Any required win32 initialization
     should take place after this block. */
  if(flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WORD wVersionRequested;
    WSADATA wsaData;
    int res;

    wVersionRequested = MAKEWORD(2, 2);
    res = WSAStartup(wVersionRequested, &wsaData);

    if(res != 0)
      /* Tell the user that we couldn't find a usable */
      /* winsock.dll.     */
      return CURLE_FAILED_INIT;

    /* Confirm that the Windows Sockets DLL supports what we need.*/
    /* Note that if the DLL supports versions greater */
    /* than wVersionRequested, it will still return */
    /* wVersionRequested in wVersion. wHighVersion contains the */
    /* highest supported version. */

    if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
      /* Tell the user that we couldn't find a usable */

      /* winsock.dll. */
      WSACleanup();
      return CURLE_FAILED_INIT;
    }
#endif
  } /* CURL_GLOBAL_WIN32 */

  QueryPerformanceFrequency(&Curl_freq);
  return CURLE_OK;
}

/* Curl_durango_cleanup() is the opposite of Curl_durango_cleanup() */
void Curl_durango_cleanup(long init_flags)
{
  if(init_flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WSACleanup();
#endif
  }
}

#endif /* DURANGO */
