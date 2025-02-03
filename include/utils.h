#ifndef UTILS_H
#define UTILS_H

#include <gmp.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../lib/lib-mesg.h"
#include "../lib/lib-misc.h"

#include <nettle/sha3.h>

#define hash_digest_len SHA3_256_DIGEST_SIZE
#define hash_context sha3_256_ctx

#define hash_function_init sha3_256_init
#define hash_function_update sha3_256_update
#define hash_function_digest sha3_256_digest

#define PRIME_ITERATIONS 12

typedef struct
{
    mpz_t x;
    mpz_t y;
} mpz_point_t;

/**
 * @brief Checks if a pointer is NULL and terminate execution if it is.
 *
 * @param[in] ptr The pointer to check for NULL.
 */
void check_null_pointer(void *ptr);

/**
 * @brief Sets a random prime number to `dst` with `l` bits, congruent to 3 mod 4.
 *
 * @param[out] dst The generated prime number.
 * @param[in] prng The random state used to generate the prime number.
 * @param[in] l The number of bits for the generated prime number.
 */
void mpz_set_lbit_prime(mpz_t dst, gmp_randstate_t prng, __uint32_t l);

/**
 * @brief Sets a random number to `dst` that is coprime to `n`.
 *
 * @param[out] dst The generated coprime number.
 * @param[in] n The modulus used to ensure coprimality.
 * @param[in] prng The random state used to generate the number.
 */
void mpz_set_random_n_coprime(mpz_t dst, mpz_t n, gmp_randstate_t prng);

/**
 * @brief Computes (`dst ^ (2 ^ (T + 1 - j))`).
 *
 * @param[out] dst The result of the exponentiation.
 * @param[in] T The total number of iterations.
 * @param[in] j The current iteration index.
 * @param[in] N The modulus used for exponentiation.
 */
void mpz_double_pow(mpz_t dst, uint32_t T, uint32_t j, mpz_t N);

/**
 * @brief Computes the right multiplicative share of (`base * prod(key_i^c)`).
 *
 * @param[out] dst The result of the multiplicative share computation.
 * @param[in] base The base value to start with.
 * @param[in] c The array of digests calculated from message to sign.
 * @param[in] key The array of key values.
 * @param[in] l The length of the coefficient and key arrays.
 * @param[in] N The modulus used for the computation.
 */
void mpz_mmul_pow_array(mpz_t dst, const mpz_t base, const uint8_t *c, const mpz_t *key, const uint32_t l, const mpz_t N);

/**
 * @brief Computes a hash digest from the given inputs.
 *
 * @param[in] m The input message string.
 * @param[in] j The round number in the protocol.
 * @param[in] Y The value calculated from players share.
 * @return Pointer to the computed hash digest.
 */
uint8_t *compute_hash_digest(const char *m, uint32_t hash_len);

/**
 * @brief Computes the modular product of an array of values.
 *
 * @param[out] dst The result of the modular product.
 * @param[in] array The array of values to multiply.
 * @param[in] size The size of the array.
 * @param[in] N The modulus used for the computation.
 */
void mpz_mmul_array(mpz_t dst, mpz_t *array, uint32_t size, mpz_t N);

/**
 * @brief Computes the modular sum of an array of values.
 *
 * @param[out] dst The result of the modular sum.
 * @param[in] array The array of values to sum.
 * @param[in] size The size of the array.
 * @param[in] N The modulus used for the computation.
 */
void mpz_madd_array(mpz_t dst, mpz_t *array, uint32_t size, mpz_t N);

/**
 * @brief Performs Shamir's secret sharing and generates shares of the secret.
 *
 * @param[out] out The output array of points that holds the shares.
 * @param[in] size The number of shares to generate.
 * @param[in] secret The secret value to share.
 * @param[in] k The threshold for reconstruction (degree of polynomial).
 * @param[in] prng The random state used for generating the polynomial.
 * @param[in] modulo The modulus used in computations.
 */
void shamir_ss(mpz_point_t *out, uint32_t size, mpz_t secret, uint32_t k, gmp_randstate_t prng, mpz_t modulo);

/**
 * @brief Multiplies two sets of Shamir secret shares and generates the resulting shares.
 *
 * @param[out] dst The output array of points that holds the result.
 * @param[in] shares_a The first set of shares.
 * @param[in] shares_b The second set of shares.
 * @param[in] size The number of shares in each set.
 * @param[in] treshold The threshold for reconstruction.
 * @param[in] prng The random state used in the computation.
 * @param[in] modulo The modulus used for computation.
 */
void mult_shamir_ss(mpz_point_t *dst, mpz_point_t *shares_a, mpz_point_t *shares_b, uint32_t size, uint32_t treshold, gmp_randstate_t prng, mpz_t modulo);

/**
 * @brief Additionate two sets of Shamir secret shares and generates the resulting shares.
 *
 * @param[out] dst The output array of points that holds the result.
 * @param[in] shares_a The first set of shares.
 * @param[in] shares_b The second set of shares.
 * @param[in] size The number of shares in each set.
 * @param[in] treshold The threshold for reconstruction.
 * @param[in] prng The random state used in the computation.
 * @param[in] modulo The modulus used for computation.
 */
void joint_shamir_ss(mpz_point_t *dst, mpz_t *secrets, uint32_t treshold, uint32_t size, gmp_randstate_t prng, mpz_t modulo);

/**
 * @brief Performs Lagrange interpolation on the provided shares to reconstruct a value.
 *
 * @param[out] result The reconstructed value.
 * @param[in] shares The shares of the secret.
 * @param[in] point The point at which to interpolate the value.
 * @param[in] size The number of shares.
 * @param[in] modulo The modulus used in the computation.
 */
void lagrange_interpolation(mpz_t result, mpz_point_t *shares, mpz_t point, uint32_t size, mpz_t modulo);

/**
 * @brief Utility to clear structure of type mpz_point_t.
 *
 * @param[in] point The point to clear.
 */
void mpz_clear_point(mpz_point_t point);

#endif