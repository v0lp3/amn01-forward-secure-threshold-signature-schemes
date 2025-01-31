#include "../include/scheme.h"

#ifndef USE_POLYNOMIAL

void keygen(context_t *ctx, public_key_t *pk, player_t *players)
{
    dealer_init_modulo(ctx, pk);

    dealer_init_players(ctx, pk, players);

    dealer_init_pk(ctx, pk);

    for (uint32_t i = 0; i < ctx->l; i++)
    {
        for (uint32_t j = 0; j < ctx->n; j++)
        {
            dealer_set_player_private_key_i(ctx, players[j].sk, i);
        }

        dealer_multiplicative_compute_public_key_i(ctx, pk, players, i);
    }
}

signature_t *sign(context_t *ctx, public_key_t *pk, player_t *players, const char *m, uint32_t j)
{
    mpz_t *r_players = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(r_players);

    mpz_t *y_players = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(y_players);

    mpz_t *z_players = (mpz_t *)malloc(ctx->n * sizeof(mpz_t));
    check_null_pointer(z_players);

    mpz_t y, z;
    mpz_inits(y, z, NULL);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        player_multiplicative_compute_r(ctx, pk, &r_players[i]);
        player_multiplicative_compute_y(ctx, pk, &y_players[i], r_players[i], j);
    }

    mpz_mmul_array(y, y_players, ctx->n, pk->N);

    uint8_t *c = compute_hash_digest(m, j, y, ctx->l);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        player_multiplicative_compute_z(ctx, pk, &z_players[i], r_players[i], players[i].sk.S, c);
    }

    mpz_mmul_array(z, z_players, ctx->n, pk->N);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clears(r_players[i], y_players[i], z_players[i], NULL);
    }

    free(c);

    signature_t *signature = signature_malloc(y, z, j);

    mpz_clears(y, z, NULL);

    return signature;
}

uint8_t update(context_t *ctx, public_key_t *pk, player_t *players, uint32_t j)
{
    if (j >= ctx->T)
    {
        return 0;
    }

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        for (uint32_t j = 0; j < ctx->l; j++)
        {
            mpz_powm_ui(players[i].sk.S[j], players[i].sk.S[j], 2, pk->N);
        }

        players[i].sk.j++;
    }

    return 1;
}

void refresh(context_t *ctx, public_key_t *pk, player_t *players)
{
    mpz_t **players_random_shares = (mpz_t **)malloc(ctx->n * sizeof(mpz_t *));
    check_null_pointer(players_random_shares);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        players_random_shares[i] = player_get_random_product_congruent_one(ctx, pk);
    }

    for (uint32_t j = 0; j < ctx->n; j++)
    {
        player_multiplicative_compute_new_secret_share(ctx, pk, players, players_random_shares, j);
    }

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        for (uint32_t j = 0; j < ctx->n; j++)
        {
            mpz_clear(players_random_shares[i][j]);
        }

        free(players_random_shares[i]);
    }

    free(players_random_shares);
}

#endif