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

uint8_t verify(context_t *ctx, public_key_t *pk, const char *m, const signature_t *s)
{
    mpz_t tmp;
    mpz_init_set_ui(tmp, 0);

    uint8_t res = 0;

    if (mpz_congruent_p(s->y, tmp, pk->N) == 0) // check if y is congruent to 0 mod n, returns non zero if congruent
    {
        uint8_t *c = player_compute_c(ctx, s->y, s->j, m);

        mpz_t left, right;
        mpz_inits(left, right, NULL);

        mpz_set(left, s->z);
        mpz_double_pow(left, pk->T, s->j, pk->N);

        mpz_mmul_pow_array(right, s->y, c, pk->U, ctx->l, pk->N);

        if (mpz_congruent_p(left, right, pk->N) != 0)
            res = 1;

        mpz_clears(left, right, NULL);

        free(c);
    }

    mpz_clear(tmp);

    return res;
}