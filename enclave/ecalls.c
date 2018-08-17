#include "trusted_header.h"


struct public_key           global_owner_pubkey;

struct secret_key           global_owner_privkey;

struct public_key           global_other_pubkey;


void
randombytes(void * dest, uint64_t l)
{
    sgx_read_rand((uint8_t *)dest, l);
}

static int
__copy_to_untrusted(void * trusted_ptr, int len, uint8_t ** untrusted_ptr)
{
    int       err       = -1;
    uint8_t * ocall_ptr = NULL;

    err = ocall_calloc((void **)&ocall_ptr, len);

    if (err || ocall_ptr == NULL) {
        log_error("allocation failed. err=%x, untrusted_ptr=%p\n", err, ocall_ptr);
        return -1;
    }

    *untrusted_ptr = ocall_ptr;

    return 0;
}

static void
__copy_from_untrusted(void * untrusted_ptr, int len, uint8_t ** trusted_ptr)
{
    uint8_t * _result = nexus_malloc(len);

    memcpy(_result, untrusted_ptr, len);

    *trusted_ptr = _result;
}

int
ecall_new_instance(const sgx_target_info_t  * target_info_IN,
                   sgx_report_t             * report_out,
                   struct public_key        * pubkey_out,
                   uint8_t                 ** sealed_privkey_out,
                   size_t                   * sealed_privkey_len_out)
{
    if (crypto_box_keypair(global_owner_pubkey.bytes, global_owner_privkey.bytes)) {
        log_error("crypto_box_keypair() FAILED\n");
        return -1;
    }

    if (create_quote(&global_owner_pubkey, target_info_IN, report_out)) {
        log_error("create_quote() FAILED\n");
        return -1;
    }

    // seal the private key and send it out
    {
        uint8_t * result = NULL;

        result = seal_data(global_owner_privkey.bytes, sizeof(struct secret_key), sealed_privkey_len_out);

        if (result == NULL) {
            log_error("sealing private key FAILED\n");
            return -1;
        }

        *sealed_privkey_out = result;
    }

    // copy out the public key
    memcpy(pubkey_out->bytes, global_owner_pubkey.bytes, sizeof(struct public_key));

    return 0;
}

int
ecall_mount_instance(struct public_key * pubkey_IN,
                     uint8_t           * sealed_privkey_in,
                     size_t              sealed_privkey_len)
{
    uint8_t * result          = NULL;
    size_t    unsealed_size   = 0;
    uint8_t * _sealed_privkey = NULL;


    // copy in the sealed key
    _sealed_privkey = nexus_malloc(sealed_privkey_len);

    memcpy(_sealed_privkey, sealed_privkey_in, sealed_privkey_len);

    result = unseal_data(_sealed_privkey, sealed_privkey_len, &unsealed_size);

    if (result == NULL) {
        nexus_free(result);

        log_error("unsealing private key FAILED\n");
        return -1;
    }

    memcpy(global_owner_pubkey.bytes, pubkey_IN->bytes, sizeof(struct public_key));
    memcpy(global_owner_privkey.bytes, result, sizeof(struct secret_key));

    // TODO check for keypair compatibility

    nexus_free(result);

    return 0;
}

int
ecall_wrap_secret(sgx_quote_t        * other_quote_IN,
                  struct public_key  * other_quote_pubkey_IN,
                  uint8_t            * secret_data_in,
                  size_t               secret_data_len,
                  struct nonce       * nonce_out,
                  uint8_t           ** wrapped_secret_out,
                  int                * wrapped_secret_len_out)
{
    uint8_t * result     = NULL;

    int       result_len = 0;

    uint8_t * secret_data_copy = NULL;

    struct nonce random_nonce = { 0 };


    if (validate_quote_and_copy_pubkey(other_quote_IN, other_quote_pubkey_IN)) {
        log_error("could not validate quote/pubkey\n");
        return -1;
    }


    __copy_from_untrusted(secret_data_in, secret_data_len, &secret_data_copy);

    randombytes(&random_nonce, sizeof(struct nonce));

    result = encrypt_data(&global_other_pubkey,
                          &global_owner_privkey,
                          secret_data_copy,
                          secret_data_len,
                          &result_len,
                          &random_nonce);

    nexus_free(secret_data_copy);

    if (result == NULL) {
        log_error("could not wrap secret\n");
        return -1;
    }


    // copy out the nonce and the wrapped secret
    memcpy(nonce_out, &random_nonce, sizeof(struct nonce));

    if (__copy_to_untrusted(result, result_len, wrapped_secret_out)) {
        log_error("could not copy data out\n");
        goto err;
    }

    *wrapped_secret_len_out = result_len;


    nexus_free(result);
    return 0;
err:
    nexus_free(result);
    return -1;
}

int
ecall_unwrap_secret(sgx_quote_t        * other_quote_IN,
                    struct public_key  * other_quote_pubkey_IN,
                    uint8_t            * wrapped_secret_in,
                    size_t               wrapped_secret_len,
                    struct nonce       * nonce_IN,
                    uint8_t           ** secret_out,
                    int                * secret_len_out)
{
    uint8_t * result     = NULL;

    int       result_len = 0;

    uint8_t * wrapped_secret_copy = NULL;


    if (validate_quote_and_copy_pubkey(other_quote_IN, other_quote_pubkey_IN)) {
        log_error("could not validate quote/pubkey\n");
        return -1;
    }


    __copy_from_untrusted(wrapped_secret_in, wrapped_secret_len, &wrapped_secret_copy);

    result = decrypt_data(&global_other_pubkey,
                          &global_owner_privkey,
                          wrapped_secret_copy,
                          wrapped_secret_len,
                          &result_len,
                          nonce_IN);

    nexus_free(wrapped_secret_copy);

    if (result == NULL) {
        log_error("could not wrap secret\n");
        return -1;
    }


    // copy out the nonce and the wrapped secret
    if (__copy_to_untrusted(result, result_len, secret_out)) {
        log_error("could not copy data out\n");
        goto err;
    }

    *secret_len_out = result_len;


    nexus_free(result);
    return 0;
err:
    nexus_free(result);
    return -1;
}
