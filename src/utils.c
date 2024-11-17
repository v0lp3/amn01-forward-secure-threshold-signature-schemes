#include "../include/utils.h"

void mpz_set_lbit_prime(mpz_t dst, gmp_randstate_t prng, __uint32_t l)
{
    mpz_t remain, modulo;

    mpz_init_set_ui(remain, 3);
    mpz_init_set_ui(modulo, 4);

    do
        mpz_urandomb(dst, prng, l);
    while (
        mpz_sizeinbase(dst, 2) < l
        // we want a number with k bits
        || mpz_probab_prime_p(dst, PRIME_ITERATIONS) == 0
        // we want a number that is prime
        || mpz_congruent_p(dst, remain, modulo) == 0
        // we want that the prime number is congruent to 3 mod 4
    );

    mpz_clears(remain, modulo, NULL);
}

void mpz_set_random_n_coprime(mpz_t dst, mpz_t n, gmp_randstate_t prng)
{
    mpz_t gcd;

    mpz_init(gcd);

    do
    {
        mpz_urandomm(dst, prng, n);

        if (mpz_even_p(dst) != 0)
            mpz_add_ui(dst, dst, 1);

        mpz_gcd(gcd, dst, n);
    } while (mpz_cmp_ui(gcd, 1) != 0);

    mpz_clear(gcd);
}

void mpz_pow_multiplicative_share(mpz_t dst, uint32_t T, uint32_t j, mpz_t N)
{
    mpz_t exponent;

    mpz_init(exponent);
    mpz_ui_pow_ui(exponent, 2, T + 1 - j);

    mpz_powm(dst, dst, exponent, N);

    mpz_clear(exponent);
}

uint8_t *compute_hash_digest(const char *m, uint8_t j, mpz_t Y)
{
    struct hash_context ctx;

    uint8_t *digests = calloc(hash_digest_len, sizeof(uint8_t));
    if (!digests)
    {
        return NULL;
    }

    hash_function_init(&ctx);

    char round_str[8];
    snprintf(round_str, sizeof(round_str), "%hhu", j);

    char *y_str = mpz_get_str(NULL, 10, Y);

    if (!y_str)
    {
        free(digests);
        return NULL;
    }

    int message_len = strlen(round_str) + strlen(y_str) + strlen(m) + 1;

    char *message = malloc(message_len);
    if (!message)
    {
        free(digests);
        free(y_str);
        return NULL;
    }

    snprintf(message, message_len, "%s%s%s", round_str, y_str, m);

    hash_function_update(&ctx, message_len - 1, (const uint8_t *)message);
    hash_function_digest(&ctx, hash_digest_len, digests);

    free(y_str);
    free(message);

    return digests;
}

void mpz_multiplicative_share(mpz_t dst, mpz_t base, uint8_t *c, mpz_t *key, uint32_t l, mpz_t N)
{
    mpz_t *tmp = (mpz_t *)malloc(l * sizeof(mpz_t));

    mpz_set(dst, base);

    for (uint8_t i = 0; i < l; i++)
    {
        mpz_init(tmp[i]);
        mpz_powm_ui(tmp[i], key[i], c[i], N);
        mpz_mul(dst, dst, tmp[i]);
        mpz_clear(tmp[i]);
    }

    mpz_mod(dst, dst, N);
    free(tmp);
}

void mpz_mmul_array(mpz_t dst, mpz_t *array, uint32_t size, mpz_t N)
{
    mpz_set(dst, array[0]);

    for (uint32_t i = 1; i < size; i++)
        mpz_mul(dst, dst, array[i]);

    mpz_mod(dst, dst, N);
}

void mpz_madd_array(mpz_t dst, mpz_t *array, uint32_t size, mpz_t N)
{
    mpz_set(dst, array[0]);

    for (uint32_t i = 1; i < size; i++)
        mpz_add(dst, dst, array[i]);

    mpz_mod(dst, dst, N);
}

void shamir_ss(mpz_point_t *out, uint32_t size, mpz_t secret, uint32_t k, gmp_randstate_t prng, mpz_t modulo)
{
    mpz_t *polynomial = polynomial = (mpz_t *)malloc(k * sizeof(mpz_t));

    mpz_init_set(polynomial[0], secret);

    for (uint32_t i = 1; i < k; i++)
    {
        mpz_init(polynomial[i]);

        do
            mpz_urandomm(polynomial[i], prng, modulo);
        while (mpz_cmp_ui(polynomial[i], 0) == 0);
    }

    for (uint32_t i = 0; i < size; i++)
    {
        mpz_init_set_ui(out[i].x, i + 1);
        mpz_init_set(out[i].y, polynomial[k - 1]);

        // Horner's method
        for (int32_t j = k - 2; j >= 0; j--)
        {
            mpz_mul(out[i].y, out[i].y, out[i].x);
            mpz_add(out[i].y, out[i].y, polynomial[j]);
            mpz_mod(out[i].y, out[i].y, modulo);
        }
    }

    for (uint32_t i = 0; i < k; i++)
    {
        mpz_clear(polynomial[i]);
    }
    free(polynomial);
}

void lagrange_interpolation(mpz_t result, mpz_point_t *shares, mpz_t point, uint32_t size, mpz_t modulo)
{
    mpz_set_ui(result, 0);

    for (uint32_t i = 0; i < size; i++)
    {
        mpz_t term;
        mpz_init_set(term, shares[i].y);

        for (uint32_t j = 0; j < size; j++)
        {
            if (j == i)
                continue;

            mpz_t num, denom;
            mpz_inits(num, denom, NULL);

            mpz_set(num, point);
            mpz_sub(num, num, shares[j].x);
            mpz_mod(num, num, modulo);

            mpz_set(denom, shares[i].x);
            mpz_sub(denom, denom, shares[j].x);

            mpz_mod(denom, denom, modulo);

            if (mpz_invert(denom, denom, modulo) == 0)
            {
                gmp_printf("Error: Inverse does not exist for denom %Zd mod %Zd\n", denom, modulo);
                exit(0);
            }

            mpz_mul(term, term, num);
            mpz_mul(term, term, denom);
            mpz_mod(term, term, modulo);

            mpz_clear(num);
            mpz_clear(denom);
        }

        mpz_add(result, result, term);
        mpz_mod(result, result, modulo);

        mpz_clear(term);
    }
}

void mpz_clear_point(mpz_point_t point)
{
    mpz_clear(point.x);
    mpz_clear(point.y);
}

void joint_shamir_ss(mpz_point_t *dst, mpz_t *secrets, uint32_t treshold, uint32_t size, gmp_randstate_t prng, mpz_t modulo)
{
    mpz_point_t **shares = (mpz_point_t **)malloc(size * sizeof(mpz_point_t *));

    for (uint32_t j = 0; j < size; j++)
    {
        shares[j] = (mpz_point_t *)malloc(size * sizeof(mpz_point_t));
        shamir_ss(shares[j], size, secrets[j], treshold, prng, modulo);
    }

    for (uint32_t i = 0; i < size; i++)
    {
        mpz_init_set_ui(dst[i].x, i + 1);
        mpz_init_set(dst[i].y, shares[0][i].y);

        for (uint32_t j = 1; j < size; j++)
        {
            mpz_add(dst[i].y, dst[i].y, shares[j][i].y);
        }

        mpz_mod(dst[i].y, dst[i].y, modulo);
    }

    for (uint32_t i = 0; i < size; i++)
    {
        for (uint32_t j = 0; j < size; j++)
        {
            mpz_clear_point(shares[i][j]);
        }

        free(shares[i]);
    }

    free(shares);
}

void mult_shamir_ss(mpz_point_t *dst, mpz_point_t *shares_a, mpz_point_t *shares_b, uint32_t size, uint32_t treshold, gmp_randstate_t prng, mpz_t modulo)
{

    mpz_t point;
    mpz_init_set_ui(point, 0);

    mpz_point_t **shares = (mpz_point_t **)malloc(size * sizeof(mpz_point_t *));

    for (uint32_t i = 0; i < size; i++)
    {
        mpz_mul(dst[i].y, shares_a[i].y, shares_b[i].y);
        mpz_mod(dst[i].y, dst[i].y, modulo);

        shares[i] = (mpz_point_t *)malloc(size * sizeof(mpz_point_t));
        shamir_ss(shares[i], size, dst[i].y, treshold, prng, modulo);
    }

    mpz_point_t *tmp = (mpz_point_t *)malloc(size * sizeof(mpz_point_t));

    for (uint32_t i = 0; i < size; i++)
    {
        mpz_inits(tmp[i].y, tmp[i].x, NULL);
    }

    for (uint32_t i = 0; i < size; i++)
    {
        for (uint32_t j = 0; j < size; j++)
        {
            mpz_set_ui(tmp[j].x, j + 1);
            mpz_set(tmp[j].y, shares[j][i].y);
        }

        mpz_set_ui(dst[i].x, i + 1);
        lagrange_interpolation(dst[i].y, tmp, point, size, modulo);
    }

    mpz_clear(point);

    for (uint32_t i = 0; i < size; i++)
    {
        for (uint32_t j = 0; j < size; j++)
        {
            mpz_clear_point(shares[i][j]);
        }

        mpz_clear_point(tmp[i]);
        free(shares[i]);
    }

    free(tmp);
    free(shares);
}
