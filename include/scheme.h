#ifndef SCHEME_H
#define SCHEME_H

#include "dealer.h"
#include "player.h"
#include "signature.h"
#include <math.h>

/**
 * @brief Simulate the protocol for key generation for all players in the system.
 */
void keygen(context_t *ctx, public_key_t *pk, player_t *players);
/**
 * @brief Simulate the protocol for signing a message using the given round number.
 *
 * @param[in] m The message to be signed.
 * @param[in] j The round number for signing.
 * @return Pointer to the generated signature
 */
signature_t *sign(context_t *ctx, public_key_t *pk, player_t *players, const char *m, uint32_t j);

/**
 * @brief Simulatet the protocol for players' keys update for the given round.
 *
 * @param[in] j The current round number.
 * @return 1 if update was successful, 0 if the final round has been reached.
 */
uint8_t update(context_t *ctx, public_key_t *pk, player_t *players, uint32_t j);

#ifndef USE_POLYNOMIAL

/**
 * @brief Simulate the protocol for refreshes of the secret shares of all players.
 */
void refresh(context_t *ctx, public_key_t *pk, player_t *players);

#endif

void cleanup(context_t *ctx, public_key_t *pk, player_t *players);

/**
 * @brief Verifies a signature against a given message.
 *
 * @param[in] m The message to verify.
 * @param[in] s The signature to verify.
 * @return 1 if the signature is valid, 0 otherwise.
 */
uint8_t verify(context_t *ctx, public_key_t *pk, const char *m, const signature_t *s);

#endif // SCHEME_H