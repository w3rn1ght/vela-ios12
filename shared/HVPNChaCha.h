// ChaCha20-Poly1305 (RFC 8439) — только расшифровка, без AAD.
// Нужен для ссылок happ://crypt5: Happ кладёт туда ChaCha20-Poly1305 с 12-байтным
// nonce, а CommonCrypto на iOS 12 этот AEAD не умеет.
#ifndef HVPN_CHACHA_H
#define HVPN_CHACHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Расшифровывает in (ciphertext || tag[16]) ключом key и 12-байтным nonce в out
/// (длиной inLen - 16). Возвращает 0 при успехе (тег совпал), -1 при ошибке.
int HVPNChaCha20Poly1305Decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *in, size_t inLen, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif
