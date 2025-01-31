#include "../include/scheme.h"

void cleanup(context_t *ctx, public_key_t *pk, player_t *players)
{
    mpz_clear(pk->N);

    for (uint32_t i = 0; i < ctx->l; i++)
    {
        mpz_clear(pk->U[i]);
    }

    free(pk->U);

    for (uint32_t i = 0; i < ctx->n; i++)
    {
        mpz_clear(players[i].sk.N);

        for (uint32_t j = 0; j < ctx->l; j++)
        {
            mpz_clear(players[i].sk.S[j]);
        }

        free(players[i].sk.S);
    }

    free(players);
}