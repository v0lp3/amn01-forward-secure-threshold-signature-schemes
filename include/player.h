#include "utils.h"
#include "context.h"

/**
 * @brief Sets a random value for a player's parameter r.
 *
 * Initializes and sets a random value for the player's parameter `r` that is coprime with the
 * public modulo `PK.N`.
 *
 * @param[out] r The output value r.
 */
static inline __attribute__((always_inline)) void player_set_r(mpz_t *r)
{
    mpz_init(*r);
    mpz_set_random_n_coprime(*r, PK.N, protocol_parameters.prng);
}

/**
 * @brief Computes the value y based on the player's parameter r and the round number j.
 *
 * @param[out] y The computed value y.
 * @param[in] r The player's parameter r.
 * @param[in] j The current round number.
 */
static inline __attribute__((always_inline)) void player_compute_y(mpz_t *y, mpz_t *r, uint32_t j)
{
    mpz_init_set(*y, *r);
    mpz_pow_multiplicative_share(*y, protocol_parameters.T, j, PK.N);
}

/**
 * @brief Computes the value z based on the player's parameters r, the array S, and the digests c.
 *
 * @param[out] z The computed value z.
 * @param[in] r The player's parameter r.
 * @param[in] S The player's secret parameter array S.
 * @param[in] c The digests array.
 * @param[in] j The current round number.
 */
static inline __attribute__((always_inline)) void player_compute_z(mpz_t *z, mpz_t *r, mpz_t *S, uint8_t *c, uint32_t j)
{
    mpz_init(*z);
    mpz_multiplicative_share(*z, *r, c, S, protocol_parameters.l, PK.N);
}

/**
 * @brief Updates the player's secret key by squaring each secret value modulo N.
 *
 * Increments the player's round number after updating the secret key.
 *
 * @param player_idx The index of the player whose key is being updated.
 */
static inline __attribute__((always_inline)) void player_update_key(uint32_t player_idx)
{
    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        mpz_powm_ui(players[player_idx].sk.S[i], players[player_idx].sk.S[i], 2, PK.N);
    }

    players[player_idx].sk.j++;
}

/**
 * @brief Generates random values such that their product is congruent to one modulo N.
 *
 * Initializes an array of random values, ensuring their product is congruent to one modulo N.
 *
 * @param[out] out The array of output values.
 * @param[in] n The number of random values to generate.
 */
static inline __attribute__((always_inline)) void player_get_randoms_congruent_one(mpz_t *out, uint32_t n)
{
    mpz_t tmp;
    mpz_inits(tmp, NULL);

    mpz_set_ui(tmp, 1);

    for (int i = 0; i < n - 1; i++)
    {
        mpz_init(out[i]);
        mpz_urandomb(out[i], protocol_parameters.prng, protocol_parameters.k);
        mpz_mul(tmp, tmp, out[i]);
        mpz_mod(tmp, tmp, PK.N);
    }

    mpz_init(out[n - 1]);

    uint32_t res = mpz_invert(out[n - 1], tmp, PK.N);

    assert(res != 0);

    mpz_clears(tmp, NULL);
}

/**
 * @brief Computes new secret shares for the player.
 *
 * Computes a new secret share for each player's secret value by multiplying with the given shares.
 *
 * @param[in, out] S The player's current secret parameters.
 * @param[in] shares The shares from other players.
 */
static inline __attribute__((always_inline)) void player_compute_new_secret_share(mpz_t *S, mpz_t *shares)
{
    mpz_t factor;
    mpz_init(factor);

    mpz_mmul_array(factor, shares, protocol_parameters.n, PK.N);

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        mpz_mul(S[i], S[i], factor);
        mpz_mod(S[i], S[i], PK.N);
    }
}

static inline __attribute__((always_inline)) void player_uses_shamir_ss(mpz_point_t *out, mpz_t s, uint32_t threshold)
{
    shamir_ss(out, protocol_parameters.n, s, threshold, protocol_parameters.prng, PK.N);
}