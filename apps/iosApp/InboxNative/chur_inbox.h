#ifndef CHUR_INBOX_H
#define CHUR_INBOX_H
#include <stdint.h>

/* Fixed buffers must be disjoint and valid for the full call. Zero means success.
 * Only the app owns the secret seed. The extension uses chur_inbox_seal only. */
enum { CHUR_INBOX_SEED_LEN = 32, CHUR_INBOX_PUBLIC_LEN = 1216,
       CHUR_INBOX_KEY_LEN = 32, CHUR_INBOX_ENVELOPE_LEN = 1168 };
int32_t chur_inbox_public(const uint8_t seed[32], uint8_t output[1216]);
int32_t chur_inbox_seal(const uint8_t recipient[1216], const uint8_t key[32], uint8_t output[1168]);
int32_t chur_inbox_open(const uint8_t seed[32], const uint8_t envelope[1168], uint8_t output[32]);
#endif
