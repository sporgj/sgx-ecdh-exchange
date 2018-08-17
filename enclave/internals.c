#include "trusted_header.h"

int
create_quote_from_pubkey(struct public_key       * pubkey,
                         const sgx_target_info_t * qe_tgt_info,
                         sgx_report_t            * report)
{
    sgx_report_data_t report_data = { 0 };

    // hash the public key into the report data (64 bytes)
    // XXX: the ECC public key is actually 64 bytes, I add this extra step for demonstration
    crypto_hash_sha512((uint8_t *)&report_data.d, pubkey->bytes, sizeof(struct public_key));

    {
        int ret = sgx_create_report(qe_tgt_info, &report_data, report);

        if (ret != SGX_SUCCESS) {
            log_error("Error creating report (ret=%x)\n", ret);
            return -1;
        }
    }

    return 0;
}

uint8_t *
seal_data(uint8_t * data, size_t size, size_t * p_sealed_len)
{
    size_t              sealed_len  = sgx_calc_sealed_data_size(0, size);

    sgx_sealed_data_t * sealed_data = nexus_malloc(sealed_len);

    {
        int ret = sgx_seal_data(0, NULL, size, data, sealed_len, sealed_data);

        if (ret != 0) {
            nexus_free(sealed_data);
            log_error("sgx_seal_data() FAILED (ret=%x)\n", ret);
            return NULL;
        }
    }

    *p_sealed_len = sealed_len;

    return (uint8_t *)sealed_data;
}


uint8_t *
unseal_data(uint8_t * data, size_t size, size_t * p_unsealed_len)
{
    sgx_sealed_data_t * sealed_data   = (sgx_sealed_data_t *)data;

    uint32_t            unsealed_len  = sgx_get_encrypt_txt_len(sealed_data);

    uint8_t           * unsealed_data = nexus_malloc(unsealed_len);

    {
        int ret = sgx_unseal_data(sealed_data, NULL, 0, unsealed_data, (uint32_t *)p_unsealed_len);

        if (ret != 0) {
            nexus_free(unsealed_data);
            log_error("sgx_unseal_data FAILED (ret=%x)\n", ret);
            return NULL;
        }
    }

    return (uint8_t *)sealed_data;
}

int
validate_quote_and_copy_pubkey(sgx_quote_t * quote, struct public_key * quote_pubkey)
{
    sgx_report_body_t * owner_body = NULL;
    sgx_report_body_t * other_body = NULL;

    sgx_report_t        owner_report;

    int ret = -1;


    /* verify the mr measurement */
    ret = sgx_create_report(NULL, NULL, &owner_report);
    if (ret != 0) {
        log_error("sgx_create_report FAILED ret=%x\n", ret);
        return -1;
    }

    owner_body = &owner_report.body;
    other_body = &quote->report_body;


    /* check the quote provenance */
    if (memcmp(&owner_body->mr_enclave, &owner_body->mr_enclave, sizeof(sgx_measurement_t))
        || memcmp(&owner_body->mr_signer, &owner_body->mr_signer, sizeof(sgx_measurement_t))) {
        log_error("enclave provenance check failed\n");
        return -1;
    }


    /* verify the other's public key */
    {
        uint8_t hash[crypto_hash_BYTES];

        crypto_hash_sha512(hash, quote_pubkey->bytes, sizeof(struct public_key));

        if (memcmp(hash, other_body->report_data.d, sizeof(hash))) {
            log_error("could not validate hash public key\n");
            return -1;
        }
    }

    memcpy(&global_other_pubkey, quote_pubkey, sizeof(struct public_key));

    return 0;
}

uint8_t *
encrypt_data(struct public_key  * pk,
             struct secret_key  * sk,
             uint8_t            * data,
             size_t               in_len,
             int                * out_len,
             struct nonce       * nonce)
{
    uint8_t   ekey[crypto_box_BEFORENMBYTES] = { 0 };

    uint8_t * plaintext                      = NULL;

    uint8_t * ciphertext                     = NULL;

    // the first 16 byte are the MAC
    int ciphertext_len                       = crypto_box_ZEROBYTES + in_len;


    if (crypto_box_beforenm(ekey, pk->bytes, sk->bytes)) {
        log_error("crypto_box_beforenm FAILED\n");
        goto err;
    }

    plaintext  = nexus_malloc(ciphertext_len);
    ciphertext = nexus_malloc(ciphertext_len);

    memcpy(plaintext + crypto_box_ZEROBYTES, data, in_len);

    // performs some salsal operation
    if (crypto_box_afternm(ciphertext, plaintext, ciphertext_len, (uint8_t *)&nonce, ekey)) {
        log_error("crypto_box_afternm FAILED\n");
        goto err;
    }

    nexus_free(plaintext);

    *out_len = ciphertext_len;

    return ciphertext;

err:
    nexus_free(plaintext);
    nexus_free(ciphertext);

    return NULL;
}

uint8_t *
decrypt_data(struct public_key  * pk,
             struct secret_key  * sk,
             uint8_t            * data,
             size_t               in_len,
             int                * plain_len,
             struct nonce       * nonce)
{
    uint8_t   ekey[crypto_box_BEFORENMBYTES] = { 0 };

    uint8_t * plaintext                      = NULL;

    uint8_t * ciphertext                     = NULL;

    // the first 16 byte are the MAC
    int ciphertext_len                       = in_len;


    if (crypto_box_beforenm(ekey, pk->bytes, sk->bytes)) {
        log_error("crypto_box_beforenm FAILED\n");
        goto err;
    }

    plaintext  = nexus_malloc(ciphertext_len);
    ciphertext = nexus_malloc(ciphertext_len);

    memcpy(ciphertext + crypto_box_ZEROBYTES, data, in_len);

    // runs the salsa stream cipher
    if (crypto_box_afternm(plaintext, ciphertext, ciphertext_len, (uint8_t *)nonce, ekey)) {
        log_error("crypto_box_afternm FAILED\n");
        goto err;
    }

    nexus_free(ciphertext);

    *plain_len = ciphertext_len - crypto_box_ZEROBYTES;

    return plaintext;

err:
    nexus_free(plaintext);
    nexus_free(ciphertext);

    return NULL;
}
