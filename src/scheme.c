#include "../include/scheme.h"

void cleanup()
{
    mpz_clear(PK.N);

    for (uint32_t i = 0; i < protocol_parameters.l; i++)
    {
        mpz_clear(PK.U[i]);
    }

    free(PK.U);

    for (uint32_t i = 0; i < protocol_parameters.n; i++)
    {
        mpz_clear(players[i].sk.N);

        for (uint32_t j = 0; j < protocol_parameters.l; j++)
        {
            mpz_clear(players[i].sk.S[j]);
        }

        free(players[i].sk.S);
    }

    free(players);
}