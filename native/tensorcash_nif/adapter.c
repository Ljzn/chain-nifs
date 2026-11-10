/* SPDX-License-Identifier: Apache-2.0
 * Seeded keygen body adapted from pinned liboqs 97f6b86b, ML-DSA-65 ref/sign.c
 * (CC0 OR Apache-2.0). See THIRD_PARTY.md. No upstream files are patched.
 * The two differences are explicit seed input and cleansing our local copies.
 * Internal symbol coupling is intentional and guarded by official vectors.
 */
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>
#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "fips202.h"
#include "sign.h"
#include "signing_workspace.h"

int tensorcash_keypair_seed(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]) {
    uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;
    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES] = K;
    seedbuf[SEEDBYTES+1] = L;
    shake256(seedbuf, sizeof(seedbuf), seedbuf, SEEDBYTES+2);
    rho = seedbuf; rhoprime = rho+SEEDBYTES; key = rhoprime+CRHBYTES;
    polyvec_matrix_expand(mat, rho);
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);
    polyveck_add(&t1, &t1, &s2);
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);
    shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
    OQS_MEM_cleanse(seedbuf, sizeof(seedbuf));
    OQS_MEM_cleanse(tr, sizeof(tr));
    OQS_MEM_cleanse(&s1, sizeof(s1)); OQS_MEM_cleanse(&s1hat, sizeof(s1hat));
    OQS_MEM_cleanse(&s2, sizeof(s2)); OQS_MEM_cleanse(&t0, sizeof(t0));
    OQS_MEM_cleanse(&t1, sizeof(t1)); OQS_MEM_cleanse(mat, sizeof(mat));
    return 0;
}

int tensorcash_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg32,
                    const uint8_t *sk, const uint8_t rnd[32]) {
    const uint8_t prefix[2] = {0, 0}; /* Pure ML-DSA, empty context */
    return tensorcash_signature_internal(sig, siglen, msg32, 32, prefix, 2, rnd, sk);
}
