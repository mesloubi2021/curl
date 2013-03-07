/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef USE_NTLM

/*
 * NTLM details:
 *
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.innovation.ch/java/ntlm.html
 */

#define DEBUG_ME 1

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "curl_ntlm.h"
#include "curl_ntlm_msgs.h"
#include "curl_ntlm_wb.h"
#include "url.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(USE_NSS)
#include "nssg.h"
#elif defined(USE_WINDOWS_SSPI)
#include "curl_sspi.h"
#endif

/* The last #include file should be: */
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x) Curl_nop_stmt
#endif

CURLcode Curl_input_ntlm(struct connectdata *conn,
                         bool proxy,         /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  CURLcode result = CURLE_OK;

#ifdef USE_NSS
  result = Curl_nss_force_init(conn->data);
  if(result)
    return result;
#endif

  ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;

  infof(conn->data, "Curl_input_ntlm(%d) with state %d\n", proxy, ntlm->state);

  /* skip initial whitespaces */
  while(*header && ISSPACE(*header))
    header++;

  if(checkprefix("NTLM", header)) {
    header += strlen("NTLM");

    while(*header && ISSPACE(*header))
      header++;

    if(*header) {
      result = Curl_ntlm_decode_type2_message(conn->data, header, ntlm);
      if(CURLE_OK != result) {
        infof(conn->data, "aborting NTLM auth on connection #%ld because the "
              "server sent a malformed type-2 header\n", conn->connection_id);
        ntlm->state = NTLMSTATE_NONE;
        return result;
      }

      /* Always respond to a type-2 message with a type-3 message - assume the
       * server knows what it's doing. Log a warning if in the wrong state,
       * though:
       *
       * NTLMSTATE_NONE: server sent a type-2 message without any prompting
       * NTLMSTATE_PICKED: ditto
       * NTLMSTATE_TYPE1_SENT: expected state; next step of authorization
       *                       continuing
       * NTLMSTATE_TYPE2_RECEIVED: we already received a type-2 and have not
       *                           responded (shouldn't have called this
       *                           function yet)
       * NTLMSTATE_TYPE3_SENT: server responded with another type-2 for some
       *                       reason
       * NTLMSTATE_AUTHORIZED: we already did a full NTLM handshake, and the
       *                       server sent another type-2 to restart auth
       */
      DEBUGASSERT(ntlm->state != NTLMSTATE_TYPE2_RECEIVED);
      if(ntlm->state != NTLMSTATE_TYPE1_SENT)
        infof(conn->data, "received an unexpected NTLM type-2 message on "
              "connection #%ld\n", conn->connection_id);
      ntlm->state = NTLMSTATE_TYPE2_RECEIVED;
    }
    else {
      /* If the server sent just "NTLM", set the state back to NONE (because we
       * may choose a different auth type based on other headers; the state
       * will be updated to PICKED if we choose to actually use NTLM auth.) If
       * it's just after we sent an NTLM message treat it as a failure (return
       * ACCESS_DENIED)
       *
       * NTLMSTATE_NONE: starting NTLM auth
       * NTLMSTATE_PICKED: ditto
       * NTLMSTATE_TYPE1_SENT: expected state; authorization failed
       * NTLMSTATE_TYPE2_RECEIVED: we already received a type-2 and have not
       *                           responded (shouldn't have called this
       *                           function yet) - treat as authorization
       *                           failed
       * NTLMSTATE_TYPE3_SENT: expected state; authorization failed
       * NTLMSTATE_AUTHORIZED: a previous NTLM handshake succeeded on this
       *                       connection, but the server requested to
       *                       authenticate again (it's allowed to do that)
       */
      curlntlm oldstate = ntlm->state;
      DEBUGASSERT(ntlm->state != NTLMSTATE_TYPE2_RECEIVED);
      ntlm->state = NTLMSTATE_NONE;
      if(oldstate == NTLMSTATE_TYPE1_SENT||oldstate == NTLMSTATE_TYPE3_SENT) {
        infof(conn->data, "NTLM handshake failure on connection #%ld\n",
              conn->connection_id);
        return CURLE_REMOTE_ACCESS_DENIED;
      }
      else if(oldstate == NTLMSTATE_TYPE2_RECEIVED) {
        infof(conn->data, "NTLM handshake failure on connection #%ld "
              "(internal error)\n", conn->connection_id);
        return CURLE_REMOTE_ACCESS_DENIED;
      }
    }
  }

  return result;
}

/*
 * This is for creating ntlm header output
 */
CURLcode Curl_output_ntlm(struct connectdata *conn,
                          bool proxy)
{
  char *base64 = NULL;
  size_t len = 0;
  CURLcode error;

  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;

  /* point to the name and password for this */
  const char *userp;
  const char *passwdp;

  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  struct auth *authp;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

#ifdef USE_NSS
  if(CURLE_OK != Curl_nss_force_init(conn->data))
    return CURLE_OUT_OF_MEMORY;
#endif

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    ntlm = &conn->proxyntlm;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    ntlm = &conn->ntlm;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  infof(conn->data, "Curl_output_ntlm(%d) with state %d\n", proxy,
        ntlm->state);

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

#ifdef USE_WINDOWS_SSPI
  if(s_hSecDll == NULL) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if(s_hSecDll == NULL)
      return err;
  }
#endif

  /* NTLMSTATE_NONE: NTLM auth was not picked; should not get here
   * NTLMSTATE_PICKED: starting of NTLM auth; send a type-1
   * NTLMSTATE_TYPE1_SENT: we already sent a type-1; we shouldn't be here until
   *                       we receive a response
   * NTLMSTATE_TYPE2_RECEIVED: send a type-3
   * NTLMSTATE_TYPE3_SENT: we already sent a type-3; we shouldn't be here
   *                       because any response ends the handshake
   * NTLMSTATE_AUTHORIZED: we already did an NTLM handshake, so just clean up;
   *                       we only get here if NTLM is the only auth type in
   *                       authp->wanted
   */
  switch(ntlm->state) {
  case NTLMSTATE_PICKED:
    /* Create a type-1 message */
    error = Curl_ntlm_create_type1_message(userp, passwdp, ntlm, &base64,
                                           &len);

    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
      free(base64);
      ntlm->state = NTLMSTATE_TYPE1_SENT;
    }
    break;

  case NTLMSTATE_TYPE2_RECEIVED:
    /* We already received the type-2 message, create a type-3 message */
    error = Curl_ntlm_create_type3_message(conn->data, userp, passwdp,
                                           ntlm, &base64, &len);
    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
      free(base64);

      ntlm->state = NTLMSTATE_TYPE3_SENT; /* we send a type-3 */
      authp->done = TRUE;
    }
    break;

  case NTLMSTATE_AUTHORIZED:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd = NULL;
    }
    authp->done = TRUE;
    break;

  default:
    /* this function should not be called in this state */
    DEBUGASSERT(FALSE);
    break;
  }

  return CURLE_OK;
}

/* If the auth type is set to NTLM, and an NTLM handshake hasn't started yet,
 * set the connection state to NTLMSTATE_PICKED so that the handshake will
 * start on that connection next time Curl_output_ntlm is called.
 * (ConnectionExists will force the connection to be reused since its state is
 * not NTLMSTATE_NONE.)
 */
void Curl_http_ntlm_checkstate(struct connectdata *conn, bool proxy)
{
  struct ntlmdata *ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;
  struct auth *auth = proxy ? &conn->data->state.authproxy :
                              &conn->data->state.authhost;

  if(ntlm->state == NTLMSTATE_NONE &&
          (auth->picked == CURLAUTH_NTLM || auth->picked == CURLAUTH_NTLM_WB))
    ntlm->state = NTLMSTATE_PICKED;
}

void Curl_http_ntlm_cleanup(struct connectdata *conn)
{
#ifdef USE_WINDOWS_SSPI
  Curl_ntlm_sspi_cleanup(&conn->ntlm);
  Curl_ntlm_sspi_cleanup(&conn->proxyntlm);
#elif defined(NTLM_WB_ENABLED)
  Curl_ntlm_wb_cleanup(conn);
#else
  (void)conn;
#endif
}

#endif /* USE_NTLM */
