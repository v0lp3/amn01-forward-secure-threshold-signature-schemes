#include "../include/scheme.h"

#ifndef USE_POLYNOMIAL

void keygen()
{
    dealer_init_modulo();

    dealer_init_players();

    dealer_init_pk();

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            dealer_set_player_private_key_i(j, i);
        }

        dealer_multiplicative_compute_public_key_i(i);
    }
}

signature_t *sign(const char *m, const uint32_t j)
{
    mpz_t *r_players = (mpz_t *)malloc(protocol_parameters.n * sizeof(mpz_t));
    check_null_pointer(r_players);

    mpz_t *y_players = (mpz_t *)malloc(protocol_parameters.n * sizeof(mpz_t));
    check_null_pointer(y_players);

    mpz_t *z_players = (mpz_t *)malloc(protocol_parameters.n * sizeof(mpz_t));
    check_null_pointer(z_players);

    mpz_t y, z;
    mpz_inits(y, z, NULL);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        player_multiplicative_compute_r(&r_players[i]);
        player_multiplicative_compute_y(&y_players[i], &r_players[i], j);
    }

    mpz_mmul_array(y, y_players, protocol_parameters.n, PK.N);

    uint8_t *c = compute_hash_digest(m, j, y);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        player_multiplicative_compute_z(&z_players[i], &r_players[i], players[i].sk.S, c);
    }

    mpz_mmul_array(z, z_players, protocol_parameters.n, PK.N);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clears(r_players[i], y_players[i], z_players[i], NULL);
    }

    free(c);

    signature_t *signature = signature_malloc(y, z, j);

    mpz_clears(y, z, NULL);

    return signature;
}

uint8_t update(uint32_t j)
{
    if (j >= protocol_parameters.T)
    {
        return 0;
    }

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        for (uint32_t j = 0; j < protocol_parameters.l; j++)
        {
            mpz_powm_ui(players[i].sk.S[j], players[i].sk.S[j], 2, PK.N);
        }

        players[i].sk.j++;
    }

    return 1;
}

void refresh()
{
    mpz_t **players_random_shares = (mpz_t **)malloc(protocol_parameters.n * sizeof(mpz_t *));
    check_null_pointer(players_random_shares);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        players_random_shares[i] = player_get_random_product_congruent_one(players_random_shares[i], protocol_parameters.n);
    }

    for (uint32_t j = 0; j < protocol_parameters.n; j++)
    {
        player_multiplicative_compute_new_secret_share(players_random_shares, j);
    }

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        for (uint32_t j = 0; j < protocol_parameters.n; j++)
        {
            mpz_clear(players_random_shares[i][j]);
        }

        free(players_random_shares[i]);
    }

    free(players_random_shares);
}

#endif