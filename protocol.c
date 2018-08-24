#include "untrusted_header.h"

sgx_enclave_id_t global_enclave_id;

sgx_spid_t global_spid = { 0x31, 0xC1, 0xBA, 0xF1, 0x1F, 0x76, 0xEB, 0xA2,
                           0x43, 0x5E, 0x6A, 0x72, 0xCE, 0x30, 0xB2, 0x2F };

const char * global_owner_filepath = "/tmp/foo.json";


struct rk_initial *
create_rk_instance()
{
    struct rk_initial * rk_instance = NULL;

    struct public_key owner_pubkey;

    uint8_t * owner_sealed_privkey = NULL;
    size_t    owner_sealed_privkey_len;

    sgx_quote_t * quote      = NULL;
    uint32_t      quote_size = 0;


    {
        sgx_target_info_t   target_info;
        sgx_epid_group_id_t epid_gid;
        sgx_report_t        report;

        int err = -1;
        int ret = -1;


        ret = sgx_init_quote(&target_info, &epid_gid);

        if (ret != SGX_SUCCESS) {
            printf("Error Initializing Quote\n");
            goto err;
        }

        err = ecall_new_instance(global_enclave_id,
                                 &ret,
                                 &target_info,
                                 &report,
                                 &owner_pubkey,
                                 &owner_sealed_privkey,
                                 &owner_sealed_privkey_len);

        if (err || ret) {
            log_error("ecall_new_instance FAILED, err=%x, ret=%d\n", err, ret);
            goto err;
        }

        quote = generate_quote(&report, &quote_size);

        if (quote == NULL) {
            log_error("generate_quote FAILED\n");
            goto err;
        }
    }

    rk_instance = nexus_malloc(sizeof(struct rk_initial));

    rk_instance->quote          = quote;
    rk_instance->quote_size     = quote_size;
    rk_instance->sealed_privkey = owner_sealed_privkey;
    rk_instance->privkey_size   = owner_sealed_privkey_len;

    memcpy(&rk_instance->pubkey, &owner_pubkey, sizeof(struct public_key));

    return rk_instance;
err:
    if (quote) {
        nexus_free(quote);
    }

    if (owner_sealed_privkey) {
        nexus_free(owner_sealed_privkey);
    }

    return NULL;
}

int
mount_rk_instance(struct rk_initial * rk_instance)
{
    int err = -1;
    int ret = -1;

    err = ecall_mount_instance(global_enclave_id,
                               &ret,
                               &rk_instance->pubkey,
                               rk_instance->sealed_privkey,
                               rk_instance->privkey_size);

    if (err || ret) {
        log_error("ecall_new_instance FAILED, err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

struct rk_exchange *
create_rk_exchange(struct rk_initial * other_instance, uint8_t * data, size_t len)
{
    struct rk_exchange * message = nexus_malloc(sizeof(struct rk_exchange));

    int err = -1;
    int ret = -1;

    err = ecall_wrap_secret(global_enclave_id,
                            &ret,
                            other_instance->quote,
                            &other_instance->pubkey,
                            data,
                            len,
                            &message->ephemeral_pubkey,
                            &message->nonce,
                            &message->ciphertext,
                            &message->ciphertext_len);

    if (err || ret) {
        nexus_free(message);

        log_error("ecall_wrap_secret FAILED\n");
        return NULL;
    }

    return message;
}

uint8_t *
extract_rk_secret(struct rk_exchange * message, int * len)
{
    uint8_t * unwrapped_secret     = NULL;
    int       unwrapped_secret_len = NULL;

    int err = -1;
    int ret = -1;

    err = ecall_unwrap_secret(global_enclave_id,
                              &ret,
                              &message->ephemeral_pubkey,
                              message->ciphertext,
                              message->ciphertext_len,
                              &message->nonce,
                              &unwrapped_secret,
                              &unwrapped_secret_len);

    if (err || ret) {
        log_error("ecall_unwrap_secret FAILED. err=%x, ret=%d\n", err, ret);
        return NULL;
    }

    *len = unwrapped_secret_len;

    return unwrapped_secret;
}



