#include "utils.h"
#include "context.h"

/**
 * @brief Sets a random value for a player's parameter r in the multiplicative scheme.
 *
 * Initializes and sets a random value for the player's parameter `r` that is coprime with the
 * public modulo `PK.N`.
 *
 * @param[out] r The output value r.
 */
static inline __attribute__((always_inline)) void player_multiplicative_compute_r(context_t *ctx, public_key_t *pk, mpz_t *r)
{
    mpz_init(*r);
    mpz_set_random_n_coprime(*r, pk->N, ctx->prng);
}

/**
 * @brief Computes the value y based on the player's parameter r and the round number j in the multiplicative scheme.
 *
 * @param[out] y The computed value y.
 * @param[in] r The player's parameter r.
 * @param[in] j The current round number.
 */
static inline __attribute__((always_inline)) void player_multiplicative_compute_y(context_t *ctx, public_key_t *pk, mpz_t *y, mpz_t r, uint32_t j)
{
    mpz_init_set(*y, r);
    mpz_double_pow(*y, ctx->T, j, pk->N);
}

/**
 * @brief Computes the value z based on the player's parameters r, the array S, and the digests c in the multiplicative scheme.
 *
 * @param[out] z The computed value z.
 * @param[in] r The player's parameter r.
 * @param[in] S The player's secret parameter array S.
 * @param[in] c The digests array.
 */
static inline __attribute__((always_inline)) void player_multiplicative_compute_z(context_t *ctx, public_key_t *pk, mpz_t *z, mpz_t r, mpz_t *S, uint8_t *c)
{
    mpz_init(*z);
    mpz_mmul_pow_array(*z, r, c, S, ctx->l, pk->N);
}

/**
 * @brief Generates random values such that their product is congruent to one modulo N.
 *
 * Initializes an array of random values, ensuring their product is congruent to one modulo N.
 *
 * @param[out] out The array of output values.
 * @param[in] n The number of random values to generate.
 */
static inline __attribute__((always_inline)) mpz_t *player_get_random_product_congruent_one(context_t *ctx, public_key_t *pk)
{
    mpz_t *out = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(out);

    mpz_t tmp;
    mpz_inits(tmp, NULL);

    mpz_set_ui(tmp, 1);

    for (int i = 0; i < ctx->n - 1; i++)
    {
        mpz_init(out[i]);
        mpz_urandomm(out[i], ctx->prng, pk->N);
        mpz_mul(tmp, tmp, out[i]);
        mpz_mod(tmp, tmp, pk->N);
    }

    mpz_init(out[ctx->n - 1]);

    uint32_t res = mpz_invert(out[ctx->n - 1], tmp, pk->N);

    assert(res != 0);

    mpz_clears(tmp, NULL);

    return out;
}

/**
 * @brief Computes new secret shares for the player.
 *
 * Computes a new secret share for each player's secret value by multiplying with the given shares.
 *
 * @param[in, out] S The player's current secret parameters.
 * @param[in] shares The shares from other players.
 */
static inline __attribute__((always_inline)) void player_multiplicative_compute_new_secret_share(context_t *ctx, public_key_t *pk, player_t *players, mpz_t **players_random_shares, uint32_t player_idx)
{
    mpz_t *shares = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(shares);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_init_set(shares[i], players_random_shares[i][player_idx]);
    }

    mpz_t factor;
    mpz_init(factor);

    mpz_mmul_array(factor, shares, ctx->n, pk->N);

    for (uint32_t i = 0; i < ctx->l; i++)
    {
        mpz_mul(players[player_idx].sk.S[i], players[player_idx].sk.S[i], factor);
        mpz_mod(players[player_idx].sk.S[i], players[player_idx].sk.S[i], pk->N);
    }

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear(shares[i]);
    }

    free(shares);
    mpz_clear(factor);
}

static inline __attribute__((always_inline)) mpz_point_t *players_polynomial_compute_r_shares(context_t *ctx, public_key_t *pk)
{
    mpz_point_t *r_shares = (mpz_point_t *)malloc(ctx->n * sizeof(mpz_point_t));
    check_null_pointer(r_shares);

    mpz_t *secrets = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(secrets);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_init(secrets[i]);
        mpz_urandomm(secrets[i], ctx->prng, pk->N);
    }

    joint_shamir_ss(r_shares, secrets, ctx->threshold, ctx->n, ctx->prng, pk->N);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear(secrets[i]);
    }

    free(secrets);

    return r_shares;
}

static inline __attribute__((always_inline)) void players_polynomial_compute_y(context_t *ctx, public_key_t *pk, mpz_t *y, mpz_point_t *r_shares, uint32_t j)
{
    mpz_init(*y);

    mpz_point_t *y_shares = (mpz_point_t *)malloc(ctx->n * sizeof(mpz_point_t));
    check_null_pointer(y_shares);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_init_set_ui(y_shares[i].x, i + 1);
        mpz_init_set(y_shares[i].y, r_shares[i].y);
    }

    uint32_t exponent = pow(2, ctx->T + 1 - j);

    for (uint32_t i = 1; i < exponent; i++)
    {
        mult_shamir_ss(y_shares, y_shares, r_shares, ctx->n, ctx->threshold, ctx->prng, pk->N);
    }

    mpz_t point;
    mpz_init_set_ui(point, 0);

    lagrange_interpolation(*y, y_shares, point, ctx->n, pk->N);

    mpz_clear(point);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear_point(y_shares[i]);
    }

    free(y_shares);
}

/**
 * @brief Utility function to get an array containing the shares of the piece `key_idx` of the key.
 *
 * In the protocol the players doesn't exchange their own shares of the key! This is only an utility function to encapsulate and reuse the code.
 *
 * @param[out] z The computed value z.
 * @param[in] r The shares of r.
 * @param[in] c The digests array.
 */
static inline mpz_point_t *player_polynomial_get_key_shares_i(context_t *ctx, player_t *players, uint32_t key_idx)
{
    mpz_point_t *key_shares = malloc(sizeof(mpz_point_t) * ctx->n);
    check_null_pointer(key_shares);

    for (uint32_t j = 0; j < ctx->n; j++)
    {
        mpz_init_set(key_shares[j].y, players[j].sk.S[key_idx]);
        mpz_init_set_ui(key_shares[j].x, j + 1);
    }

    return key_shares;
}

/**
 * @brief Computes the value z in the polynomial scheme.
 *
 * @param[out] z The computed value z.
 * @param[in] r The shares of r.
 * @param[in] c The digests array.
 */
static inline __attribute__((always_inline)) void players_polynomial_compute_z(context_t *ctx, public_key_t *pk, player_t *players, mpz_t *z, uint8_t *c, mpz_point_t *r_shares)
{
    mpz_init(*z);

    mpz_point_t *z_shares = (mpz_point_t *)malloc(ctx->n * sizeof(mpz_point_t));
    check_null_pointer(z_shares);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_init_set_ui(z_shares[i].x, i + 1);
        mpz_init_set(z_shares[i].y, r_shares[i].y);
    }

    mpz_t point;
    mpz_init_set_ui(point, 0);

    for (uint32_t i = 0; i < ctx->l; i++)
    {
        if (c[i] == 0)
        {
            continue;
        }

        mpz_point_t *key_shares = player_polynomial_get_key_shares_i(ctx, players, i);
        mpz_point_t *result = player_polynomial_get_key_shares_i(ctx, players, i);

        mult_shamir_ss(z_shares, z_shares, result, ctx->n, ctx->threshold, ctx->prng, pk->N);

        for (uint32_t j = 0; j < ctx->n; j++)
        {
            mpz_clear_point(key_shares[j]);
            mpz_clear_point(result[j]);
        }

        free(result);
        free(key_shares);
    }

    lagrange_interpolation(*z, z_shares, point, ctx->n, pk->N);

    mpz_clear(point);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear_point(z_shares[i]);
    }

    free(z_shares);
}

static inline __attribute__((always_inline)) uint8_t *player_compute_c(context_t *ctx, const mpz_t Y, const uint32_t j, const char *m)
{
    char round_str[8];

    uint8_t *c = calloc(ctx->l, sizeof(uint8_t));

    snprintf(round_str, sizeof(round_str), "%hhu", j);

    char *y_str = mpz_get_str(NULL, 10, Y);

    check_null_pointer(y_str);

    size_t message_len = strlen(round_str) + strlen(y_str) + strlen(m) + 1;

    char *message = calloc(message_len, sizeof(char));

    check_null_pointer(message);

    snprintf(message, message_len, "%s%s%s", round_str, y_str, m);

    uint8_t *digests = compute_hash_digest(message, ctx->l / 8);

    free(message);

    for (int i = 0; i < ctx->l / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            c[i * 8 + j] = (digests[i] >> (7 - j)) & 1;
        }
    }

    free(digests);

    return c;
}