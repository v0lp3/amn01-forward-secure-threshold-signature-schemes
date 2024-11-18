#include "scheme.h"

void end_test(const char *test_name);

void test_simple_sign_verify();

void test_round_update_sign_verify();

void test_forge_sign_verify();

#ifndef USE_POLYNOMIAL
void test_refresh_sign_verify();
#endif