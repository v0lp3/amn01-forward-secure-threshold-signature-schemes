#include "../include/scheme.h"

#ifdef USE_POLYNOMIAL

void keygen(context_t *ctx, public_key_t *pk, player_t *players)
{
    dealer_init_modulo(ctx, pk);

    dealer_init_players(ctx, pk, players);

    dealer_init_pk(ctx, pk);

    for (uint32_t i = 0; i < ctx->l; i++)
    {
        mpz_t s;
        mpz_init(s);
        mpz_set_random_n_coprime(s, pk->N, ctx->prng);

        dealer_polynomial_compute_public_key_i(pk, s, i);

        mpz_point_t *shares = (mpz_point_t *)malloc(ctx->n * sizeof(mpz_point_t));
        check_null_pointer(shares);

        dealer_uses_shamir_ss(ctx, pk, shares, s);

        for (uint32_t j = 0; j < ctx->n; j++)
        {
            mpz_init_set(players[j].sk.S[i], shares[j].y);
            mpz_clear_point(shares[j]);
        }

        mpz_clear(s);
        free(shares);
    }
}

signature_t *sign(context_t *ctx, public_key_t *pk, player_t *players, const char *m, uint32_t j)
{
    mpz_t y, z;

    mpz_point_t *r_shares = players_polynomial_compute_r_shares(ctx, pk);

    players_polynomial_compute_y(ctx, pk, &y, r_shares, j);

    uint8_t *c = compute_hash_digest(m, j, y);

    players_polynomial_compute_z(ctx, pk, players, &z, c, r_shares);

    signature_t *signature = signature_malloc(y, z, j);

    mpz_clears(y, z, NULL);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear_point(r_shares[i]);
    }

    free(r_shares);
    free(c);

    return signature;
}

uint8_t update(context_t *ctx, public_key_t *pk, player_t *players, uint32_t j)
{
    if (j >= ctx->T)
    {
        return 0;
    }

    for (uint32_t i = 0; i < ctx->l; i++)
    {

        mpz_point_t *tmp = player_polynomial_get_key_shares_i(ctx, players, i);

        mult_shamir_ss(tmp, tmp, tmp, ctx->n, ctx->threshold, ctx->prng, pk->N);

        for (uint32_t j = 0; j < ctx->n; j++)
        {
            mpz_set(players[j].sk.S[i], tmp[j].y);
            mpz_clear_point(tmp[j]);
        }

        free(tmp);
    }

    return 1;
}

#endif