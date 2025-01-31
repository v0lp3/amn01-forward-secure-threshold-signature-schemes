#include "../include/tests.h"

void init_test(context_t *ctx, public_key_t *PK, player_t **players, const char *test_name)
{
    printf("[%s] Test started\n", test_name);

    gmp_randinit_default(ctx->prng);
    gmp_randseed_os_rng(ctx->prng, 128);

    *players = (player_t *)malloc(ctx->n * sizeof(player_t));
}

void end_test(context_t *ctx, public_key_t *PK, player_t *players, const char *test_name)
{
    printf("[%s] Test passed\n", test_name);

    gmp_randclear(ctx->prng);

    cleanup(ctx, PK, players);
}

void test_simple_sign_verify()
{
    context_t protocol_parameters;
    public_key_t PK;
    player_t *players;

    protocol_parameters.k = 1024;
    protocol_parameters.l = 160;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    init_test(&protocol_parameters, &PK, &players, __func__);

    keygen(&protocol_parameters, &PK, players);

    const char *m = __func__;

    signature_t *signature = sign(&protocol_parameters, &PK, players, m, 0);

    assert(verify(&protocol_parameters, &PK, m, signature) == 1);

    signature_free(signature);

    end_test(&protocol_parameters, &PK, players, __func__);
}

void test_round_update_sign_verify()
{
    context_t protocol_parameters;
    public_key_t PK;
    player_t *players;

    protocol_parameters.k = 1024;
    protocol_parameters.l = 160;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    init_test(&protocol_parameters, &PK, &players, __func__);

    keygen(&protocol_parameters, &PK, players);

    update(&protocol_parameters, &PK, players, 1);

    const char *m = __func__;

    signature_t *signature = sign(&protocol_parameters, &PK, players, m, 0);

    assert(verify(&protocol_parameters, &PK, m, signature) == 0);

    signature_free(signature);

    signature = sign(&protocol_parameters, &PK, players, m, 1);

    assert(verify(&protocol_parameters, &PK, m, signature) == 1);

    signature_free(signature);

    end_test(&protocol_parameters, &PK, players, __func__);
}

void test_forge_sign_verify()
{
    context_t protocol_parameters;
    public_key_t PK;
    player_t *players;

    protocol_parameters.k = 1024;
    protocol_parameters.l = 160;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    init_test(&protocol_parameters, &PK, &players, __func__);

    keygen(&protocol_parameters, &PK, players);

    const char *m = __func__;

    signature_t *signature = sign(&protocol_parameters, &PK, players, m, 0);

    const char *fake_m = "fake message";

    assert(verify(&protocol_parameters, &PK, m, signature) == 1);
    assert(verify(&protocol_parameters, &PK, fake_m, signature) == 0);

    signature_free(signature);

    end_test(&protocol_parameters, &PK, players, __func__);
}

#ifndef USE_POLYNOMIAL

void test_refresh_sign_verify()
{
    context_t protocol_parameters;
    public_key_t PK;
    player_t *players;

    protocol_parameters.k = 1024;
    protocol_parameters.l = 160;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    init_test(&protocol_parameters, &PK, &players, __func__);

    keygen(&protocol_parameters, &PK, players);

    const char *m = __func__;

    refresh(&protocol_parameters, &PK, players);

    signature_t *signature = sign(&protocol_parameters, &PK, players, m, 0);

    const char *fake_m = "fake message";

    assert(verify(&protocol_parameters, &PK, m, signature) == 1);
    assert(verify(&protocol_parameters, &PK, fake_m, signature) == 0);

    signature_free(signature);

    end_test(&protocol_parameters, &PK, players, __func__);
}

#endif