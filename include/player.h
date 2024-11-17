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
static inline __attribute__((always_inline)) void player_multiplicative_compute_r(mpz_t *r)
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
static inline __attribute__((always_inline)) void player_multiplicative_compute_y(mpz_t *y, mpz_t *r, uint32_t j)
{
    mpz_init_set(*y, *r);
    mpz_double_pow(*y, protocol_parameters.T, j, PK.N);
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
static inline __attribute__((always_inline)) void player_multiplicative_compute_z(mpz_t *z, mpz_t *r, mpz_t *S, uint8_t *c, uint32_t j)
{
    mpz_init(*z);
    mpz_mmul_pow_array(*z, *r, c, S, protocol_parameters.l, PK.N);
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

static inline __attribute__((always_inline)) mpz_point_t *players_polynomial_compute_r_shares()
{
    mpz_point_t *r_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));
    check_null_pointer(r_shares);

    mpz_t *secrets = (mpz_t *)malloc(protocol_parameters.n * sizeof(mpz_t));
    check_null_pointer(secrets);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_init(secrets[i]);
        mpz_urandomm(secrets[i], protocol_parameters.prng, PK.N);
    }

    joint_shamir_ss(r_shares, secrets, protocol_parameters.threshold, protocol_parameters.n, protocol_parameters.prng, PK.N);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear(secrets[i]);
    }

    free(secrets);

    return r_shares;
}

static inline __attribute__((always_inline)) void players_polynomial_compute_y(mpz_t *y, mpz_point_t *r_shares, uint32_t j)
{
    mpz_init(*y);

    mpz_point_t *y_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));
    check_null_pointer(y_shares);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_init_set_ui(y_shares[i].x, i + 1);
        mpz_init_set(y_shares[i].y, r_shares[i].y);
    }

    uint32_t exponent = pow(2, protocol_parameters.T + 1 - j);

    for (uint32_t i = 1; i < exponent; i++)
    {
        mult_shamir_ss(y_shares, y_shares, r_shares, protocol_parameters.n, protocol_parameters.threshold, protocol_parameters.prng, PK.N);
    }

    mpz_t point;
    mpz_init_set_ui(point, 0);

    lagrange_interpolation(*y, y_shares, point, protocol_parameters.n, PK.N);

    mpz_clear(point);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear_point(y_shares[i]);
    }

    free(y_shares);
}

static inline mpz_point_t *player_polynomial_get_key_i_shares(uint32_t key_idx)
{
    mpz_point_t *key_shares = malloc(sizeof(mpz_point_t) * protocol_parameters.n);
    check_null_pointer(key_shares);

    for (uint32_t j = 0; j < protocol_parameters.n; j++)
    {
        mpz_init_set(key_shares[j].y, players[j].sk.S[key_idx]);
        mpz_init_set_ui(key_shares[j].x, j + 1);
    }

    return key_shares;
}

static inline __attribute__((always_inline)) void players_polynomial_compute_z(mpz_t *z, uint8_t *c, mpz_point_t *r_shares)
{
    mpz_init(*z);

    mpz_point_t *z_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));
    check_null_pointer(z_shares);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_init_set_ui(z_shares[i].x, i + 1);
        mpz_init_set(z_shares[i].y, r_shares[i].y);
    }

    mpz_t point;
    mpz_init_set_ui(point, 0);

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        if (c[i] == 0)
        {
            continue;
        }

        mpz_point_t *key_shares = player_polynomial_get_key_i_shares(i);
        mpz_point_t *result = player_polynomial_get_key_i_shares(i);

        for (uint32_t k = 1; k < c[i]; k++)
        {
            mult_shamir_ss(result, result, key_shares, protocol_parameters.n, protocol_parameters.threshold, protocol_parameters.prng, PK.N);
        }

        mult_shamir_ss(z_shares, z_shares, result, protocol_parameters.n, protocol_parameters.threshold, protocol_parameters.prng, PK.N);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_clear_point(key_shares[j]);
            mpz_clear_point(result[j]);
        }

        free(result);
        free(key_shares);
    }

    lagrange_interpolation(*z, z_shares, point, protocol_parameters.n, PK.N);

    mpz_clear(point);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear_point(z_shares[i]);
    }

    free(z_shares);
}
