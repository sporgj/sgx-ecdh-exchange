#pragma once

#include <sgx_report.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <assert.h>
#include <string.h>

#include <common_structures.h>

#include "enclave_t.h"

#include "tweetnacl.h"

#include "libnexus_trusted/nexus_log.h"
#include "libnexus_trusted/nexus_util.h"


struct secret_key {
    uint8_t  bytes[crypto_box_SECRETKEYBYTES];
} __attribute__((packed));


extern struct public_key           global_owner_pubkey;

extern struct secret_key           global_owner_privkey;

extern struct public_key           global_other_pubkey;


int
validate_quote_and_copy_pubkey(sgx_quote_t * quote, struct public_key * quote_pubkey);


/**
 * Given the specified public key, generate a report (which is incorporated into a quote)
 */
int
create_quote_from_pubkey(struct public_key       * pubkey,
                         const sgx_target_info_t * qe_tgt_info,
                         sgx_report_t            * report);

/**
 * Seals the data using the SGX sealing key
 */
uint8_t *
seal_data(uint8_t * data, size_t size, size_t * p_sealed_len);

/**
 * Unseals data sealed with the sgx sealing key
 */
uint8_t *
unseal_data(uint8_t * data, size_t size, size_t * p_unsealed_len);

/**
 * Encrypts data with common key derived from specified (pk, sk)
 */
uint8_t *
encrypt_data(struct public_key  * pk,
             struct secret_key  * sk,
             uint8_t            * data,
             size_t               in_len,
             int                * out_len,
             struct nonce       * nonce);

/**
 * Encrypts data with common key derived from specified (pk, sk)
 */
uint8_t *
decrypt_data(struct public_key  * pk,
             struct secret_key  * sk,
             uint8_t            * data,
             size_t               in_len,
             int                * plain_len,
             struct nonce       * nonce);

