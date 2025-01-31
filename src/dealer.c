#include "../include/dealer.h"

void dealer_init_modulo(context_t* ctx, public_key_t* pk)
{
    mpz_t p, q;

    mpz_inits(p, q, pk->N, NULL);

    mpz_set_lbit_prime(p, ctx->prng, ctx->k / 2);

    do
    {
        mpz_set_lbit_prime(q, ctx->prng, ctx->k / 2);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(pk->N, p, q);

    mpz_clears(p, q, NULL);
}

void dealer_init_players(context_t* ctx, public_key_t* pk, player_t* players)
{
    for (uint32_t i = 0; i < ctx->n; i++)
    {
        players[i].id = i;

        mpz_init_set(players[i].sk.N, pk->N);

        players[i].sk.j = 0;
        players[i].sk.T = ctx->T;
        players[i].sk.S = (mpz_t *)malloc(ctx->l * sizeof(mpz_t));

        check_null_pointer(players[i].sk.S);
    }
}

void dealer_init_pk(context_t* ctx, public_key_t* pk)
{
    pk->T = ctx->T;
    pk->U = (mpz_t *)malloc(ctx->l * sizeof(mpz_t));

    check_null_pointer(pk->U);
}