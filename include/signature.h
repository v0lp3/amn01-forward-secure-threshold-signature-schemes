#include "context.h"
#include "utils.h"
#include "stdlib.h"

/**
 * @brief Allocates and initializes a new signature object.
 *
 * @param[in] y The value for `y` in the signature.
 * @param[in] z The value for `z` in the signature.
 * @param[in] j The value `j` that indicates the round when the signature was valid.
 * @return Pointer to the newly allocated `signature_t` structure.
 */
signature_t *signature_malloc(mpz_t y, mpz_t z, uint8_t j);

/**
 * @brief Frees the memory associated with a signature object.
 *
 * @param[in] s Pointer to the `signature_t` structure to be freed.
 */
void signature_free(signature_t *s);

/**
 * @brief Verifies a signature against a given message.
 *
 * @param[in] m The message to verify.
 * @param[in] s The signature to verify.
 * @return 1 if the signature is valid, 0 otherwise.
 */
uint8_t verify(char *m, signature_t *s);