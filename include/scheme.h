
#include "dealer.h"
#include "player.h"
#include "signature.h"
#include <math.h>

/**
 * @brief Simulate the protocol for key generation for all players in the system.
 */
void keygen();
/**
 * @brief Simulate the protocol for signing a message using the given round number.
 *
 * @param[in] m The message to be signed.
 * @param[in] j The round number for signing.
 * @return Pointer to the generated signature
 */
signature_t *sign(char *m, uint32_t j);

/**
 * @brief Simulatet the protocol for players' keys update for the given round.
 *
 * @param[in] j The current round number.
 * @return 1 if update was successful, 0 if the final round has been reached.
 */
uint8_t update(uint32_t j);

/**
 * @brief Simulate the protocol for refreshes of the secret shares of all players.
 */
void refresh();