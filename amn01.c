#include "include/tests.h"

#define LOG_LEVEL msg_very_verbose

int main()
{
    set_messaging_level(LOG_LEVEL);

    test_simple_sign_verify();
    test_round_update_sign_verify();
    test_forge_sign_verify();

#ifndef USE_POLYNOMIAL
    test_refresh_sign_verify();
#endif
}