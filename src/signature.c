#include "../include/signature.h"

signature_t *signature_malloc(mpz_t y, mpz_t z, uint8_t j)
{
    signature_t *sigma = (signature_t *)malloc(sizeof(signature_t));
    check_null_pointer(sigma);

    mpz_init_set(sigma->y, y);
    mpz_init_set(sigma->z, z);

    sigma->j = j;

    return sigma;
}

void signature_free(signature_t *s)
{
    mpz_clear(s->y);
    mpz_clear(s->z);
    free(s);
}

uint8_t verify(context_t *ctx, public_key_t *pk, const char *m, const signature_t *s)
{
    mpz_t tmp;
    mpz_init_set_ui(tmp, 0);

    uint8_t res = 0;

    if (mpz_congruent_p(s->y, tmp, pk->N) == 0) // check if y is congruent to 0 mod n, returns non zero if congruent
    {
        uint8_t *c = compute_hash_digest(m, s->j, s->y);

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