#pragma once

#include "common_structures.h"


struct rk_initial {
    sgx_quote_t       * quote;

    uint32_t            quote_size;

    struct public_key   pubkey;

    uint8_t           * sealed_privkey;

    uint32_t            privkey_size;
};


struct rk_exchange {
    struct public_key   ephemeral_pubkey;

    struct nonce        nonce;

    uint8_t           * ciphertext;

    uint32_t            ciphertext_len;
};



int
store_init_message(const char * filepath, struct rk_initial * message);

struct rk_initial *
fetch_init_message(const char * filepath);

void
free_init_message(struct rk_initial * message);



int
store_xchg_message(const char * filepath, struct rk_exchange * message);

struct rk_exchange *
fetch_xchg_message(const char * filepath);

void
free_xchg_message(struct rk_exchange * message);
