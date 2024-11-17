#include "../include/scheme.h"

void keygen()
{
    dealer_set_modulo();

    dealer_init_players();

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        mpz_t s;
        dealer_polynomial_set_secret_compute_public_key_i(&s, i);

        mpz_point_t *shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));

        dealer_uses_shamir_ss(shares, s, protocol_parameters.threshold);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_init_set(players[j].sk.S[i], shares[j].y);
            mpz_clear_point(shares[j]);
        }

        free(shares);
    }
}

signature_t *sign(char *m, uint32_t j)
{
    mpz_point_t *r_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));
    mpz_point_t *z_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));

    mpz_t *secrets = (mpz_t *)malloc(protocol_parameters.n * sizeof(mpz_t));

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_init(secrets[i]);
        mpz_urandomm(secrets[i], protocol_parameters.prng, PK.N);
    }

    joint_shamir_ss(r_shares, secrets, protocol_parameters.threshold, protocol_parameters.n, protocol_parameters.prng, PK.N);

    mpz_point_t *y_shares = (mpz_point_t *)malloc(protocol_parameters.n * sizeof(mpz_point_t));

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_init_set_ui(y_shares[i].x, i + 1);
        mpz_init_set(y_shares[i].y, r_shares[i].y);

        mpz_init_set_ui(z_shares[i].x, i + 1);
        mpz_init_set(z_shares[i].y, r_shares[i].y);
    }

    uint32_t exponent = pow(2, protocol_parameters.T + 1 - j);

    for (uint32_t i = 1; i < exponent; i++)
    {
        mult_shamir_ss(y_shares, y_shares, r_shares, protocol_parameters.n, protocol_parameters.threshold, protocol_parameters.prng, PK.N);
    }

    mpz_t y, z;
    mpz_inits(y, z, NULL);

    mpz_t point;
    mpz_init_set_ui(point, 0);

    lagrange_interpolation(y, y_shares, point, protocol_parameters.n, PK.N);

    uint8_t *c = compute_hash_digest(m, j, y);

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        if (c[i] == 0)
        {
            continue;
        }

        mpz_point_t *key_shares = malloc(sizeof(mpz_point_t) * protocol_parameters.n);
        mpz_point_t *result = malloc(sizeof(mpz_point_t) * protocol_parameters.n);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_init_set(key_shares[j].y, players[j].sk.S[i]);
            mpz_init_set_ui(key_shares[j].x, j + 1);

            mpz_init_set(result[j].y, players[j].sk.S[i]);
            mpz_init_set_ui(result[j].x, j + 1);
        }

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

    lagrange_interpolation(z, z_shares, point, protocol_parameters.n, PK.N);

    signature_t *signature = signature_malloc(y, z, j);

    mpz_clears(y, z, point, NULL);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear_point(r_shares[i]);
        mpz_clear_point(y_shares[i]);
        mpz_clear_point(z_shares[i]);
        mpz_clear(secrets[i]);
    }

    free(r_shares);
    free(y_shares);
    free(z_shares);
    free(secrets);
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
        mpz_point_t *tmp = malloc(sizeof(mpz_point_t) * protocol_parameters.n);

        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_init_set(tmp[j].y, players[j].sk.S[i]);
            mpz_init_set_ui(tmp[j].x, j + 1);
        }

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