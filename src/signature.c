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

