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
static inline __attribute__((always_inline)) void dealer_set_modulo()
{
    mpz_t p, q;

    mpz_inits(p, q, PK.N, NULL);

    mpz_set_lbit_prime(p, protocol_parameters.prng, protocol_parameters.k / 2);

    do
    {
        mpz_set_lbit_prime(q, protocol_parameters.prng, protocol_parameters.k / 2);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(PK.N, p, q);

    mpz_clears(p, q, NULL);
}

/**
 * @brief Initializes the players array with secret keys and parameters.
 *
 * Allocates memory for the players and initializes each player's ID, secret key (sk),
 * and secret parameters. The secret key includes the public modulo (N), the current round,
 * and an array of secret values (S) of lenght l.
 *
 */
static inline __attribute__((always_inline)) void dealer_init_players()
{
    players = (player_t *)malloc(protocol_parameters.n * sizeof(player_t));

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        players[i].id = i;

        mpz_init_set(players[i].sk.N, PK.N);

        players[i].sk.j = 0;
        players[i].sk.T = protocol_parameters.T;
        players[i].sk.S = (mpz_t *)malloc(protocol_parameters.l * sizeof(mpz_t));
    }
}

/**
 * @brief Sets a random value in player's secret key that is coprime with the public modulo.
 *
 * @param player_idx The index of the player.
 * @param key_idx The index of the secret key value to be set.
 *
 */
static inline __attribute__((always_inline)) void dealer_set_player_private_key_i(uint32_t player_idx, uint32_t key_idx)
{
    mpz_init(players[player_idx].sk.S[key_idx]);
    mpz_set_random_n_coprime(players[player_idx].sk.S[key_idx], players[player_idx].sk.N, protocol_parameters.prng);
}

/**
 * @brief Computes the public key component for a specific index.
 *
 * Initializes and computes the product of all players' secret keys at the given index and
 * stores the result in the public key array `PK.U`. The result is then exponentiated by a
 * power of 2 to complete the computation.
 *
 * @param key_idx The index of the public key value to be computed.
 *
 */
static inline __attribute__((always_inline)) void dealer_multiplicative_compute_public_key_i(uint32_t key_idx)
{
    if (key_idx == 0)
    {
        PK.T = protocol_parameters.T;
        PK.U = (mpz_t *)malloc(protocol_parameters.l * sizeof(mpz_t));
    }

    mpz_init(PK.U[key_idx]);

    mpz_set(PK.U[key_idx], players[0].sk.S[key_idx]);

    for (uint32_t i = 1; i < protocol_parameters.n; i++)
    {
        mpz_mul(PK.U[key_idx], PK.U[key_idx], players[i].sk.S[key_idx]);
        mpz_mod(PK.U[key_idx], PK.U[key_idx], PK.N);
    }

    mpz_pow_multiplicative_share(PK.U[key_idx], PK.T, 0, PK.N);
}

static inline __attribute__((always_inline)) void dealer_polynomial_set_secret_compute_public_key_i(mpz_t *s, uint32_t key_idx)
{
    if (key_idx == 0)
    {
        PK.T = protocol_parameters.T;
        PK.U = (mpz_t *)malloc(protocol_parameters.l * sizeof(mpz_t));
    }

    mpz_init(*s);
    mpz_set_random_n_coprime(*s, PK.N, protocol_parameters.prng);

    mpz_init_set(PK.U[key_idx], *s);

    mpz_pow_multiplicative_share(PK.U[key_idx], PK.T, 0, PK.N);
}

static inline __attribute__((always_inline)) void dealer_uses_shamir_ss(mpz_point_t *out, mpz_t s, uint32_t threshold)
{
    shamir_ss(out, protocol_parameters.n, s, threshold, protocol_parameters.prng, PK.N);
}