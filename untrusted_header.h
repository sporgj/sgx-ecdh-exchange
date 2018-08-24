#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_urts.h>
#include <sgx_tseal.h>

#include <sgx_quote.h>
#include <sgx_uae_service.h>

#include <time.h>

#include "enclave_u.h"

#include "common_structures.h"
#include "messages.h"
#include "protocol.h"

#include "libnexus/nexus_log.h"
#include "libnexus/nexus_util.h"
#include "libnexus/nexus_json.h"
#include "libnexus/nexus_encode.h"
#include "libnexus/nexus_raw_file.h"


#define ENCLAVE_PATH "./enclave/enclave.signed.so"

#define SGX_VERIFY_URL "https://test-as.sgx.trustedservices.intel.com/attestation/sgx/v2/report"

#define SGX_CERT_PATH "./tls-cert/prognosticlab-sgx.cert"
#define SGX_KEY_PATH "./tls-cert/client.key"
#define SGX_KEY_PASS "foobar"


extern sgx_enclave_id_t global_enclave_id;

extern sgx_spid_t global_spid;

extern const char * global_owner_filepath;



/* quote.c */
sgx_quote_t *
generate_quote(sgx_report_t * report, uint32_t * p_quote_size);

int
validate_quote(sgx_quote_t * quote, uint32_t quote_size);



/* protocol.c */

struct rk_initial *
create_rk_instance();

int
mount_rk_instance(struct rk_initial * rk_instance);

struct rk_exchange *
create_rk_exchange(struct rk_initial * other_instance, uint8_t * data, size_t len);

uint8_t *
extract_rk_secret(struct rk_exchange * message, int * len);

