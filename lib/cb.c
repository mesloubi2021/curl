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

static CURLcode update_string(char **str, const char *newstr)
{
  DEBUGASSERT(str);

  if(!newstr)
    newstr = "";

  Curl_safefree(*str);
  *str = strdup(newstr);
  if(!*str)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/* Copy the given string into the curl_easy_setopt string area. */
static CURLcode update_set_string(struct SessionHandle *data, int key,
                                  const char *newstr)
{
  return update_string(&data->set.str[key], newstr);
}

/*
 * curl_cb_set_credentials allows an application to update the username and
 * password (normally set with curl_easy_setopt) at any time, including from
 * within a callback. It is not safe to call from another thread, though.
 *
 * type can be CURLAUTH_TYPE_HOST or CURLAUTH_TYPE_PROXY. Any other value will
 * cause this function to return CURLE_BAD_FUNCTION_ARGUMENT.
 *
 * NOTE: if the credentials are set to NULL or to empty strings, empty
 * credentials are sent to the server. To stop sending credentials to the
 * server, use curl_cb_clear_credentials.
 */
CURLcode curl_cb_set_credentials(CURL *curl, curl_auth_type type,
                                 const char *username, const char *password)
{
  CURLcode result;
  struct SessionHandle *data = (struct SessionHandle *)curl;
  struct connectdata *conn = data->state.current_conn;

  DEBUGASSERT(data && conn);

  switch(type) {
  case CURLAUTH_TYPE_HOST:
    result = update_set_string(data, STRING_USERNAME, username);
    result = update_set_string(data, STRING_PASSWORD, password) || result;
    result = update_string(&conn->user, username) || result;
    result = update_string(&conn->passwd, password) || result;
    if(CURLE_OK == result)
      data->state.current_conn->bits.user_passwd = TRUE;
    return result;
  case CURLAUTH_TYPE_PROXY:
    result = update_set_string(data, STRING_PROXYUSERNAME, username);
    result = update_set_string(data, STRING_PROXYPASSWORD, password) || result;
    result = update_string(&conn->proxyuser, username) || result;
    result = update_string(&conn->proxypasswd, password) || result;
    if(CURLE_OK == result)
      data->state.current_conn->bits.proxy_user_passwd = TRUE;
    return result;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}

/*
 * curl_cb_clear_credentials allows an application to remove the username and
 * password (set with curl_easy_setopt or curl_cb_set_credentials) at any time,
 * including from within a callback. It is not safe to call from another
 * thread, though.
 *
 * type can be CURLAUTH_TYPE_HOST or CURLAUTH_TYPE_PROXY. Any other value will
 * cause this function to return CURLE_BAD_FUNCTION_ARGUMENT.
 */
CURLcode curl_cb_clear_credentials(CURL *curl, curl_auth_type type)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  struct connectdata *conn = data->state.current_conn;

  DEBUGASSERT(data && conn);

  /* Curl_safefree includes setting the variable to NULL. */
  switch(type) {
  case CURLAUTH_TYPE_HOST:
    Curl_safefree(data->set.str[STRING_USERNAME]);
    Curl_safefree(data->set.str[STRING_PASSWORD]);
    Curl_safefree(conn->user);
    Curl_safefree(conn->passwd);
    data->state.current_conn->bits.user_passwd = FALSE;

    /* If our protocol needs a password and we have none, use the defaults */
    if(conn->handler->flags & PROTOPT_NEEDSPWD) {
      conn->user = strdup(CURL_DEFAULT_USER);
      if(!conn->user)
        return CURLE_OUT_OF_MEMORY;
    }

    return CURLE_OK;
  case CURLAUTH_TYPE_PROXY:
    Curl_safefree(data->set.str[STRING_PROXYUSERNAME]);
    Curl_safefree(data->set.str[STRING_PROXYPASSWORD]);
    Curl_safefree(conn->proxyuser);
    Curl_safefree(conn->proxypasswd);
    data->state.current_conn->bits.proxy_user_passwd = FALSE;
    return CURLE_OK;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}
