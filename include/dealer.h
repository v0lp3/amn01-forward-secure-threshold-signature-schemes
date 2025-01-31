#include "utils.h"
#include "context.h"

/**
 * @brief Sets the public key modulo (N) as the product of two distinct prime numbers.
 *
 * This function generates two distinct prime numbers p and q, each with half the bit-length
 * specified in the protocol parameters, and sets the value of the public key modulo N
 * as the product of these two primes.
 *
 */
void dealer_init_modulo(context_t *ctx, public_key_t *pk);

/**
 * @brief Initializes the players array with secret keys and parameters.
 *
 * Allocates memory for the players and initializes each player's ID, secret key (sk),
 * and secret parameters. The secret key includes the public modulo (N), the current round,
 * and an array of secret values (S) of lenght l.
 *
 */
void dealer_init_players(context_t *ctx, public_key_t *pk, player_t *players);

/**
 * @brief Initialize public parameters in the protocol.
 *
 */
void dealer_init_pk(context_t *ctx, public_key_t *pk);

/**
 * @brief Sets a random value in player's secret key that is coprime with the public modulo.
 *
 * @param player_idx The index of the player.
 * @param key_idx The index of the secret key value to be set.
 *
 */
static inline __attribute__((always_inline)) void dealer_set_player_private_key_i(context_t *ctx, secret_key_t player_sk, uint32_t key_idx)
{
    mpz_init(player_sk.S[key_idx]);
    mpz_set_random_n_coprime(player_sk.S[key_idx], player_sk.N, ctx->prng);
}

/**
 * @brief Computes the public key component for a specific index.
 *
 * @param key_idx The index of the public key value to be computed.
 *
 */
static inline __attribute__((always_inline)) void dealer_multiplicative_compute_public_key_i(context_t *ctx, public_key_t *pk, player_t *players, uint32_t key_idx)
{
    mpz_init(pk->U[key_idx]);

    mpz_set(pk->U[key_idx], players[0].sk.S[key_idx]);

    for (uint32_t i = 1; i < ctx->n; i++)
    {
        mpz_mul(pk->U[key_idx], pk->U[key_idx], players[i].sk.S[key_idx]);
        mpz_mod(pk->U[key_idx], pk->U[key_idx], pk->N);
    }

    mpz_double_pow(pk->U[key_idx], pk->T, 0, pk->N);
}

/**
 * @brief This function is used in the polynomial protocol to compute the value of the public key.
 *
 */
static inline __attribute__((always_inline)) void dealer_polynomial_compute_public_key_i(public_key_t* pk, mpz_t s, uint32_t key_idx)
{
    mpz_init_set(pk->U[key_idx], s);

    mpz_double_pow(pk->U[key_idx], pk->T, 0, pk->N);
}

/**
 * @brief Dealer uses shamir secret sharing in the keygen to generate shares of the key.
 *
 */
static inline __attribute__((always_inline)) void dealer_uses_shamir_ss(context_t* ctx, public_key_t* pk, mpz_point_t *out, mpz_t s)
{
    shamir_ss(out, ctx->n, s, ctx->threshold, ctx->prng, pk->N);
}