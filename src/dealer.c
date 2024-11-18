#include "../include/dealer.h"

void dealer_init_modulo()
{
    mpz_t p, q;

    mpz_inits(p, q, PK.N, NULL);

    mpz_set_lbit_prime(p, protocol_parameters.prng, protocol_parameters.k / 2);

    do
    {
        mpz_set_lbit_prime(q, protocol_parameters.prng, protocol_parameters.k / 2);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(PK.N, p, q);

    mpz_clears(p, q, NULL);
}

void dealer_init_players()
{
    players = (player_t *)malloc(protocol_parameters.n * sizeof(player_t));

    check_null_pointer(players);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        players[i].id = i;

        mpz_init_set(players[i].sk.N, PK.N);

        players[i].sk.j = 0;
        players[i].sk.T = protocol_parameters.T;
        players[i].sk.S = (mpz_t *)malloc(protocol_parameters.l * sizeof(mpz_t));

        check_null_pointer(players[i].sk.S);
    }
}

void dealer_init_pk()
{
    PK.T = protocol_parameters.T;
    PK.U = (mpz_t *)malloc(protocol_parameters.l * sizeof(mpz_t));

    check_null_pointer(PK.U);
}