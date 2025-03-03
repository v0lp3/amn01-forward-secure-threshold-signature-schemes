#ifndef CONTEXT_H
#define CONTEXT_H

#include <gmp.h>
#include <stdint.h>

typedef struct
{
    uint32_t l;
    uint32_t n;
    uint32_t k;
    uint32_t T;
    uint32_t threshold;
    gmp_randstate_t prng;
} context_t;

typedef struct
{
    mpz_t N;
    mpz_t *S;

    uint32_t T;
    uint32_t j;
} secret_key_t;

typedef struct
{
    mpz_t N;
    mpz_t *U;

    uint32_t T;
} public_key_t;

typedef struct
{
    __uint32_t id;
    secret_key_t sk;
} player_t;

typedef struct
{
    uint8_t j;
    mpz_t y;
    mpz_t z;

} signature_t;

#endif // CONTEXT_H