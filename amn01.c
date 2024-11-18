#include "include/tests.h"

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

    test_simple_sign_verify();
    test_round_update_sign_verify();
    test_forge_sign_verify();

    #ifndef USE_POLYNOMIAL
    test_refresh_sign_verify();
    #endif
    
    
    gmp_randclear(protocol_parameters.prng);
}