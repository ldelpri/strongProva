/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
 * Copyright (C) 2014 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Author: Roberto Sassu <roberto.sassu@polito.it>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "oat_attest_listener.h"

#include <daemon.h>
#include <json.h>

#define MAX_BUF_LEN 256

typedef struct private_oat_attest_listener_t private_oat_attest_listener_t;

/**
 * Private data of an oat_attest_listener_t object.
 */
struct private_oat_attest_listener_t {

	/**
	 * Public oat_attest_listener_t interface.
	 */
	oat_attest_listener_t public;
};

bool oat_attest_request(char *peer_hostname, char *peer_cert_digest)
{
	struct json_tokener *tokener;
	chunk_t data, response = chunk_empty;
	json_object *jresponse, *response_array;
	status_t status;
	char uri[MAX_BUF_LEN] = { 0 };
	char user_reqs[MAX_BUF_LEN] = { 0 };
	char *oat_server, *request_id, *ima_level;
	bool attest_result = false;

	/* build the OAT request */
	json_object *jrequest = json_object_new_object();
	json_object *jarray = json_object_new_array();
	json_object *jstring_host = json_object_new_string(peer_hostname);
	json_object *jstring_reqs;

	ima_level = lib->settings->get_str(lib->settings,
					   "%s.plugins.oat-attest.ima_level",
					   NULL, lib->ns);
	if (!ima_level)
		ima_level = "l4_ima_all_ok";

	snprintf(user_reqs, MAX_BUF_LEN,
		 "load-time+check-cert,l_req=%s|>=,cert_digest=%s", ima_level,
		 peer_cert_digest);

	jstring_reqs = json_object_new_string(user_reqs);
	json_object_array_add(jarray, jstring_host);
	json_object_object_add(jrequest, "hosts", jarray);
	json_object_object_add(jrequest, "analysisType", jstring_reqs);
	data = chunk_from_str((char*)json_object_to_json_string(jrequest));
	DBG0(DBG_LIB, "json string: %s, len: %d\n", data.ptr, data.len);

	/* send the request to OAT */
	oat_server = lib->settings->get_str(lib->settings,
					    "%s.plugins.oat-attest.oat_server",
					    NULL, lib->ns);
	if (!oat_server) {
		DBG0(DBG_LIB, "The oat_server parameter must be set\n");
		goto out;
	}

	request_id = lib->settings->get_str(lib->settings,
					    "%s.plugins.oat-attest.request_id",
					    NULL, lib->ns);

	if (request_id) {
		snprintf(uri, MAX_BUF_LEN, "https://%s:8443/AttestationService/resources/PostHosts?requestId=%s", oat_server, request_id);
		status = lib->fetcher->fetch(lib->fetcher, uri, &response,
					FETCH_TIMEOUT, 120,
					FETCH_REQUEST_TYPE, "application/json",
					FETCH_END);
	} else {
		snprintf(uri, MAX_BUF_LEN, "https://%s:8443/AttestationService/resources/PollHosts", oat_server);
		status = lib->fetcher->fetch(lib->fetcher, uri, &response,
					FETCH_TIMEOUT, 120,
					FETCH_REQUEST_TYPE, "application/json",
					FETCH_REQUEST_DATA, data,
					FETCH_END);
	}
	char *msg = strndup(response.ptr, response.len);
	DBG0(DBG_LIB, "returned response: %s\n", msg);
	free(msg);

	if (status != SUCCESS)
		goto out;

	/* parse the OAT response */
	tokener = json_tokener_new();
	jresponse = json_tokener_parse_ex(tokener, response.ptr, response.len);
	json_object_object_get_ex(jresponse, "hosts", &response_array);
	int i, count = json_object_array_length(response_array);
	for (i = 0; i < count; i++) {
		json_object *jvalue = json_object_array_get_idx(response_array, i);
		json_object *host_name;
		json_object *trust_lvl;

		json_object_object_get_ex(jvalue, "host_name", &host_name);
		if (strcmp(json_object_get_string(host_name), peer_hostname) == 0) {
			json_object_object_get_ex(jvalue, "trust_lvl", &trust_lvl);
			attest_result = strcmp(json_object_get_string(trust_lvl), "trusted") == 0;
			DBG0(DBG_LIB, "host %s status %s", peer_hostname, json_object_get_string(trust_lvl));
			break;
		}
	}

	json_tokener_free(tokener);
	free(response.ptr);
	json_object_put(jresponse);
	json_object_put(response_array);

out:
	json_object_put(jstring_host);
	json_object_put(jstring_reqs);
	json_object_put(jarray);
	json_object_put(jrequest);

	return attest_result;
}

METHOD(listener_t, authorize, bool,
	private_oat_attest_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	enumerator_t *rounds;
	certificate_t *cert;
	auth_cfg_t *auth;
	bool attest_peer;

	/* Check all rounds in final hook, as local authentication data are
	 * not completely available after round-invocation. */
	if (!final)
	{
		return TRUE;
	}

	attest_peer = lib->settings->get_bool(lib->settings,
					      "%s.plugins.oat-attest.attest_peer",
					      FALSE, lib->ns);
	if (!attest_peer)
	{
		return TRUE;
	}

	/* collect remote certificates */
	rounds = ike_sa->create_auth_cfg_enumerator(ike_sa, FALSE);
	while (rounds->enumerate(rounds, &auth))
	{
		cert = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
		if (cert)
		{
			enumerator_t *parts;
			id_part_t part;
			chunk_t data;
			identification_t *id;
			hasher_t *hasher;
			chunk_t encoded;
			chunk_t cert_digest;

			/* extract common name for OAT query */
			id = cert->get_subject(cert);
			parts = id->create_part_enumerator(id);
			while (parts->enumerate(parts, &part, &data))
			{
				if (part == ID_PART_RDN_CN) {
					DBG0(DBG_LIB, "Peer CN: %s\n", data.ptr);
					break;
				}
			}
			parts->destroy(parts);

			/* calculate and display the digest of the peer cert */
			if (cert->get_encoding(cert, CERT_ASN1_DER, &encoded)) {
				char digest_str[41];
				char *hostname;
				int rc;

				hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
				rc = hasher->allocate_hash(hasher, encoded, &cert_digest);
				chunk_to_hex(cert_digest, digest_str, false);
				DBG0(DBG_LIB, "Cert hash %s", digest_str);
				hostname = strndup(data.ptr, data.len);
				*success = oat_attest_request(hostname, digest_str);
				free(hostname);
				chunk_clear(&cert_digest);
				chunk_clear(&encoded);
				DESTROY_IF(hasher);
			}
			chunk_clear(&data);
		}
	}
	rounds->destroy(rounds);
	return TRUE;
}

METHOD(oat_attest_listener_t, destroy, void,
	private_oat_attest_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
oat_attest_listener_t *oat_attest_listener_create()
{
	private_oat_attest_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
