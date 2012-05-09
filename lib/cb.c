/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 Research In Motion Limited. All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

#include <curl/curl.h>

#include "urldata.h"

/* The last #include file should be: */
#include "memdebug.h"

/* Copy the given string into the curl_easy_setopt string area. */
static CURLcode update_set_string(struct SessionHandle *data, int key,
                                  const char *newstr)
{
  if(!newstr)
    newstr = "";

  Curl_safefree(data->set.str[key]);
  data->set.str[key] = strdup(newstr);
  if(!data->set.str[key])
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/*
 */
CURLcode curl_cb_set_credentials(CURL *curl, curl_auth_type type,
                                 const char *username, const char *password)
{
  CURLcode result;
  struct SessionHandle *data = (struct SessionHandle *)curl;
  DEBUGASSERT(data && data->state.current_conn);
  switch(type) {
  case CURLAUTH_TYPE_HOST:
    result = update_set_string(data, STRING_USERNAME, username);
    if(CURLE_OK != result)
      return result;
    data->state.current_conn->bits.user_passwd = TRUE;
    return update_set_string(data, STRING_PASSWORD, password);
  case CURLAUTH_TYPE_PROXY:
    result = update_set_string(data, STRING_PROXYUSERNAME, username);
    if(CURLE_OK != result)
      return result;
    data->state.current_conn->bits.proxy_user_passwd = TRUE;
    return update_set_string(data, STRING_PROXYPASSWORD, password);
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}

/*
 */
CURLcode curl_cb_clear_credentials(CURL *curl, curl_auth_type type)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  DEBUGASSERT(data && data->state.current_conn);
  // Curl_safefree includes setting the variable to NULL.
  switch(type) {
  case CURLAUTH_TYPE_HOST:
    Curl_safefree(data->set.str[STRING_USERNAME]);
    Curl_safefree(data->set.str[STRING_PASSWORD]);
    data->state.current_conn->bits.user_passwd = FALSE;
    return CURLE_OK;
  case CURLAUTH_TYPE_PROXY:
    Curl_safefree(data->set.str[STRING_PROXYUSERNAME]);
    Curl_safefree(data->set.str[STRING_PROXYPASSWORD]);
    data->state.current_conn->bits.proxy_user_passwd = FALSE;
    return CURLE_OK;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}
