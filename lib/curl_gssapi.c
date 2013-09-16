/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_GSSAPI

#include "curl_gssapi.h"
#include "sendf.h"

#include <krb5.h>
#include <gssapi_krb5.h>

/**
*	Prints the error message associated with a failed krb5 call
*/
void curl_krb5_print_error_message(krb5_context krb_context, int error_code, struct SessionHandle *data) {
	const char *errormsg = krb5_get_error_message(krb_context, error_code);
	infof(data, "KRB5_ERROR: %s \n" , errormsg);
	infof(data, "\n Freeing all krb5 related data structures \n");
	krb5_free_error_message(krb_context, errormsg);
}

void curl_krb5_free_local_data(krb5_context krb_context, krb5_ccache ccache, 
							   krb5_creds *creds, krb5_principal principal,
							   krb5_get_init_creds_opt *opts, krb5_keytab ktab) {
	if(principal != NULL)
		krb5_free_principal(krb_context, principal);

	krb5_free_cred_contents(krb_context, creds);
	
	if(ccache != NULL) {
		krb5_cc_close(krb_context, ccache);
	}
	if(opts != NULL)
		krb5_get_init_creds_opt_free(krb_context, opts);
	
	if(ktab != NULL)
		krb5_kt_close(krb_context, ktab);

	if(krb_context != NULL)
		krb5_free_context(krb_context);

}

void curl_krb5_free_local_data_memory(krb5_context krb_context, krb5_ccache ccache, 
							   krb5_creds *creds, krb5_principal principal,
							   krb5_get_init_creds_opt *opts, krb5_keytab ktab) {
	if(principal != NULL)
		krb5_free_principal(krb_context, principal);

	krb5_free_cred_contents(krb_context, creds);
	
	if(ccache != NULL) {
		krb5_cc_destroy(krb_context, ccache);	//this is for in memory credential cache
	}
	if(opts != NULL)
		krb5_get_init_creds_opt_free(krb_context, opts);

	if(ktab != NULL)
		krb5_kt_close(krb_context, ktab);

	if(krb_context != NULL)
		krb5_free_context(krb_context);
}

OM_uint32 Curl_gss_init_sec_context(
    struct connectdata *conn,
    OM_uint32 * minor_status,
    gss_ctx_id_t * context,
    gss_name_t target_name,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_buffer_t output_token,
    OM_uint32 * ret_flags)
{ 
	krb5_context krb_context = NULL;							/* Kerberos context object */
	krb5_ccache ccache = NULL;									
    krb5_creds creds;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_principal principal = NULL;
    krb5_keytab ktab = NULL;
	OM_uint32 min_stat, maj_stat;
	char *cachename = NULL;
    char *keytabfile = "";
	OM_uint32 major_status;

	struct SessionHandle *data = conn->data;
	int ret;
	OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
	conn->data->curl_gss_creds = GSS_C_NO_CREDENTIAL;
	
	memset(&creds, 0, sizeof(creds));

	if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_POLICY_FLAG) {
		#ifdef GSS_C_DELEG_POLICY_FLAG
			req_flags |= GSS_C_DELEG_POLICY_FLAG;
		#else
		    infof(data, "warning: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not "
		        "compiled in\n");
		#endif
	}

	if(data->set.gssapi_delegation & CURLGSSAPI_DELEGATION_FLAG)
		req_flags |= GSS_C_DELEG_FLAG;

	if((ret = krb5_init_context(&krb_context)) != 0) {
		 curl_krb5_print_error_message(krb_context, ret, data);
		 curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		 return CURLE_KERBEROS_AUTH_FAILED;
	}
  
	printf("\n The principal used in this is %s", conn->user);
	if ((ret = krb5_parse_name(krb_context, conn->user, &principal)) != 0) {
		 curl_krb5_print_error_message(krb_context, ret, data);
		 curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		 return CURLE_KERBEROS_AUTH_FAILED;
	}
	
	if ((ret = krb5_get_init_creds_opt_alloc (krb_context , &opts)) != 0) {
         curl_krb5_print_error_message(krb_context, ret, data);
		 curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
	     return CURLE_KERBEROS_AUTH_FAILED;
	}  

	if (conn->bits.user_keytab) {
		 infof(data, "KRB5_DATA: Keytab location is %s \n", conn->keytab_location);
		 printf("\n The keytab used in this is %s", conn->keytab_location); 
		 if ((ret = krb5_kt_resolve(krb_context, conn->keytab_location, &ktab)) != 0) {
			curl_krb5_print_error_message(krb_context, ret, data);
			curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		    return CURLE_KERBEROS_AUTH_FAILED;
		 }
		 if ((ret = krb5_get_init_creds_keytab(krb_context, &creds, principal, ktab, 0, NULL, opts)) != 0) {
			 curl_krb5_print_error_message(krb_context, ret, data);
			 curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		     return CURLE_KERBEROS_AUTH_FAILED;
		 }
    } else if(conn->bits.user_passwd) {
		  infof(data,"KRB5_DATA: Using the user password method \n");
		  if ((ret = krb5_get_init_creds_password(krb_context,&creds,principal,conn->passwd,NULL,NULL,0,NULL,opts)) != 0 ) {
				curl_krb5_print_error_message(krb_context, ret, data);
				curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
				return CURLE_KERBEROS_AUTH_FAILED;
		  }
	} else if(conn->bits.credential_cache) {
		infof(data, "Resolving given credential cache \n");
		infof(data, "KRB5_DATA: Credential cache location is %s \n", conn->credential_cache);
		if ((ret = krb5_cc_resolve(krb_context, conn->credential_cache, &ccache))!=0) {
			   curl_krb5_print_error_message(krb_context, ret, data);
			   curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
			   return CURLE_KERBEROS_AUTH_FAILED;
		}
	} else if(conn->data->isIntermediateServer) {
		infof(data, "KRB5_DATA: Curl is acting as intermediate server \n");
		conn->data->curl_gss_creds = conn->data->deleg_gss_creds;
		major_status = gss_init_sec_context(minor_status,
                              conn->data->curl_gss_creds, /* cred_handle */
                              context,
                              target_name,
                              GSS_C_NO_OID, /* mech_type */
                              req_flags,
                              0, /* time_req */
                              input_chan_bindings,
                              input_token,
                              NULL, /* actual_mech_type */
                              output_token,
                              ret_flags,
                              NULL /* time_rec */);
		curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		return major_status;
	} else {		
	      infof(data, "KRB5_DATA: Passed no password/keytab location, using default credentials\n ");
		  conn->data->curl_gss_creds = GSS_C_NO_CREDENTIAL;
		  major_status = gss_init_sec_context(minor_status,
                              conn->data->curl_gss_creds, /* cred_handle */
                              context,
                              target_name,
                              GSS_C_NO_OID, /* mech_type */
                              req_flags,
                              0, /* time_req */
                              input_chan_bindings,
                              input_token,
                              NULL, /* actual_mech_type */
                              output_token,
                              ret_flags,
                              NULL /* time_rec */);
		  curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
		  return major_status;
    }
	if(!conn->bits.credential_cache) {
		infof(data, "Creating new credential cache, since none specified \n");
		if((ret = krb5_cc_new_unique( krb_context, "MEMORY", NULL, &ccache)) != 0) {
			 curl_krb5_print_error_message(krb_context, ret, data);
			 curl_krb5_free_local_data_memory(krb_context, ccache, &creds, principal, opts, ktab);
			 return CURLE_KERBEROS_AUTH_FAILED;
		}
		infof(data, "Initializing credential cache \n");
		if ((ret = krb5_cc_initialize(krb_context, ccache, principal))!=0) {
		     curl_krb5_print_error_message(krb_context, ret, data);
			 curl_krb5_free_local_data_memory(krb_context, ccache, &creds, principal, opts, ktab);
			 return CURLE_KERBEROS_AUTH_FAILED;
		}
		infof(data, "Storing credential within credential cache \n");
		if ((ret = krb5_cc_store_cred(krb_context,ccache,&creds)) != 0) {
			 curl_krb5_print_error_message(krb_context, ret, data);
			 curl_krb5_free_local_data_memory(krb_context, ccache, &creds, principal, opts, ktab);
			 return CURLE_KERBEROS_AUTH_FAILED ;
		}
	}
	infof(data, "Attempting to import the credential \n");
	if ((maj_stat = gss_krb5_import_cred(&min_stat,
	    ccache,
		principal,
		NULL,
		&conn->data->curl_gss_creds))!=0) {
			  infof(data, "Importing krb5 credential into gss credentials failed\n");
			  curl_krb5_print_error_message(krb_context, min_stat, data);
			  if(conn->bits.credential_cache)
				  curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
			  else
				  curl_krb5_free_local_data_memory(krb_context, ccache, &creds, principal, opts, ktab);
			  return CURLE_KERBEROS_AUTH_FAILED;
		}

	infof(data, "Able to convert the credential \n");
	infof(data, "Attempting init sec context \n");

	printf("\n It is running gss init context\ n");
	major_status = gss_init_sec_context(minor_status,
                              conn->data->curl_gss_creds, /* cred_handle */
                              context,
                              target_name,
                              GSS_C_NO_OID, /* mech_type */
                              req_flags,
                              0, /* time_req */
                              input_chan_bindings,
                              input_token,
                              NULL, /* actual_mech_type */
                              output_token,
                              ret_flags,
                              NULL /* time_rec */);

	if(conn->bits.credential_cache)
        curl_krb5_free_local_data(krb_context, ccache, &creds, principal, opts, ktab);
    else
        curl_krb5_free_local_data_memory(krb_context, ccache, &creds, principal, opts, ktab);

	return major_status;
}

#endif /* HAVE_GSSAPI */
