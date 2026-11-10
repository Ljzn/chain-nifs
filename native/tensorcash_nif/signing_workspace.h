#ifndef TENSORCASH_SIGNING_WORKSPACE_H
#define TENSORCASH_SIGNING_WORKSPACE_H
#include <stdint.h>
#include <stddef.h>
int tensorcash_signature_internal(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t rnd[32], const uint8_t *sk);
#endif
