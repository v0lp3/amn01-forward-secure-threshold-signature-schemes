#include "../include/scheme.h"

#ifdef USE_POLYNOMIAL

void keygen()
{
    dealer_init_modulo();

    dealer_init_players();

    dealer_init_pk();

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        mpz_t s;
        mpz_init(s);
        mpz_set_random_n_coprime(s, PK.N, protocol_parameters.prng);

        dealer_polynomial_compute_public_key_i(s, i);

        mpz_point_t *shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));
        check_null_pointer(shares);

        dealer_uses_shamir_ss(shares, s);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_init_set(players[j].sk.S[i], shares[j].y);
            mpz_clear_point(shares[j]);
        }

        mpz_clear(s);
        free(shares);
    }
}

signature_t *sign(const char *m, const uint32_t j)
{
    mpz_t y, z;

    mpz_point_t *r_shares = players_polynomial_compute_r_shares();

    players_polynomial_compute_y(&y, r_shares, j);

    uint8_t *c = compute_hash_digest(m, j, y);

    players_polynomial_compute_z(&z, c, r_shares);

    signature_t *signature = signature_malloc(y, z, j);

    mpz_clears(y, z, NULL);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear_point(r_shares[i]);
    }

    free(r_shares);
    free(c);

    return signature;
}

uint8_t update(uint32_t j)
{
    if (j >= protocol_parameters.T)
    {
        return 0;
    }

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {

        mpz_point_t *tmp = player_polynomial_get_key_shares_i(i);

        mult_shamir_ss(tmp, tmp, tmp, protocol_parameters.n, protocol_parameters.threshold, protocol_parameters.prng, PK.N);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_set(players[j].sk.S[i], tmp[j].y);
            mpz_clear_point(tmp[j]);
        }

        free(tmp);
    }

    return 1;
}

#endif