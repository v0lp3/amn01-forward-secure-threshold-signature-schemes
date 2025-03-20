#include "../include/bench.h"

void bench_sign()
{
    context_t protocol_parameters;
    public_key_t PK;
    player_t *players;

    stats_t timing;
    elapsed_time_t time;

    protocol_parameters.k = 1024;
    protocol_parameters.l = 60;
    protocol_parameters.n = 5;
    protocol_parameters.threshold = 3;
    protocol_parameters.T = 10;

    printf("[%s] Benchmark started\n", __func__);

    gmp_randinit_default(protocol_parameters.prng);
    gmp_randseed_os_rng(protocol_parameters.prng, 128);

    players = (player_t *)malloc(protocol_parameters.n * sizeof(player_t));

    const char *m = __func__;

    calibrate_timing_methods();

    perform_oneshot_wc_time_sampling(
        time, tu_millis,
        {
            keygen(&protocol_parameters, &PK, players);
        });

    printf_et("keygen: ", time, tu_millis, "\n");

    signature_t *signature;

    perform_wc_time_sampling_period(
        timing, BENCH_SAMPLING_TIME, MAX_SAMPLES, tu_millis,
        {
            signature = sign(&protocol_parameters, &PK, players, m, 0);
        },
        {});

    printf_stats("sign", timing, "");

    uint8_t res;

    perform_wc_time_sampling_period(
        timing, BENCH_SAMPLING_TIME, MAX_SAMPLES, tu_millis,
        {
            res = verify(&protocol_parameters, &PK, m, signature);
        },
        {});

    printf_stats("verify", timing, "");

    assert(res == 1);

    puts("----------------------------------------");

    signature_free(signature);
    gmp_randclear(protocol_parameters.prng);
    cleanup(&protocol_parameters, &PK, players);
}