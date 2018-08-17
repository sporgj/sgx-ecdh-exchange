#pragma once

#include <stdint.h>

#include "tweetnacl.h"

#define SECRET_BYTES        16

#define NONCE_BYTES         16


struct secret {
    uint8_t  bytes[SECRET_BYTES];
};

struct public_key {
    uint8_t  bytes[crypto_box_PUBLICKEYBYTES];
} __attribute__((packed));

struct nonce {
    uint8_t  bytes[crypto_box_NONCEBYTES];
} __attribute__((packed));



/**
 * Creates the quote of the public key
 */
struct xchg_message1 {
    uint16_t quote_size;
    uint16_t signature_size;
    uint8_t  data[0];
} __attribute__((packed));


struct xchg_message2 {
    struct nonce    nonce;
    uint8_t         data[0];
} __attribute__((packed));
