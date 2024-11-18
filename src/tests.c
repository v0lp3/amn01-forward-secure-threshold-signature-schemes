#include "../include/tests.h"

void end_test(const char *test_name)
{
    printf("[%s] Test passed\n", test_name);
    cleanup();
}

void test_simple_sign_verify()
{
    keygen();

    const char *m = __func__;

    signature_t *signature = sign(m, 0);

    assert(verify(m, signature) == 1);

    signature_free(signature);

    end_test(__func__);
}

void test_round_update_sign_verify()
{
    keygen();

    update(1);

    const char *m = __func__;

    signature_t *signature = sign(m, 0);

    assert(verify(m, signature) == 0);

    signature_free(signature);

    signature = sign(m, 1);

    assert(verify(m, signature) == 1);

    signature_free(signature);

    end_test(__func__);
}

void test_forge_sign_verify()
{
    keygen();

    const char *m = __func__;

    signature_t *signature = sign(m, 0);

    const char *fake_m = "fake message";

    assert(verify(m, signature) == 1);
    assert(verify(fake_m, signature) == 0);

    signature_free(signature);

    end_test(__func__);
}

#ifndef USE_POLYNOMIAL

void test_refresh_sign_verify()
{
    keygen();

    const char *m = __func__;

    refresh();

    signature_t *signature = sign(m, 0);

    const char *fake_m = "fake message";

    assert(verify(m, signature) == 1);
    assert(verify(fake_m, signature) == 0);

    signature_free(signature);

    end_test(__func__);
}

#endif