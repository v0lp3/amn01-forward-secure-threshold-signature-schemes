#include "src/polynomial-scheme.c"
// #include "src/multiplicative-scheme.c"
context_t protocol_parameters;
public_key_t PK;
player_t *players;

#define LOG_LEVEL msg_very_verbose

int main()
{
    set_messaging_level(LOG_LEVEL);

    protocol_parameters.k = 1024;
    protocol_parameters.l = 16;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    gmp_randinit_default(protocol_parameters.prng);
    gmp_randseed_os_rng(protocol_parameters.prng, 128);

    keygen();

    update(1);

    char *m = "amn01 signature test";
    signature_t *signature = sign(m, 1);

    pmesg_mpz(msg_verbose, "y", signature->y);
    pmesg_mpz(msg_verbose, "z", signature->z);

    printf("%d\n", verify(m, signature));

    signature_free(signature);
}