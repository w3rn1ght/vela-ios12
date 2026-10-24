// ChaCha20-Poly1305 (RFC 8439). Реализация намеренно простая и переносимая:
// без таблиц, только 32-битные операции (armv7/arm64, без зависимостей).
#include "HVPNChaCha.h"

#include <string.h>

static uint32_t hvpn_ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void hvpn_st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void hvpn_st64(uint8_t *p, uint64_t v) {
    hvpn_st32(p, (uint32_t)(v & 0xffffffffu));
    hvpn_st32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t hvpn_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define HVPN_QR(a, b, c, d)                     \
    do {                                        \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = hvpn_rotl32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = hvpn_rotl32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = hvpn_rotl32(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = hvpn_rotl32(x[b], 7);  \
    } while (0)

static void hvpn_chacha20_block(const uint8_t key[32], uint32_t counter,
                                const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t st[16];
    uint32_t x[16];

    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = hvpn_ld32(key + i * 4);
    st[12] = counter;
    st[13] = hvpn_ld32(nonce + 0);
    st[14] = hvpn_ld32(nonce + 4);
    st[15] = hvpn_ld32(nonce + 8);

    memcpy(x, st, sizeof(x));
    for (int i = 0; i < 10; i++) {
        HVPN_QR(0, 4, 8, 12);
        HVPN_QR(1, 5, 9, 13);
        HVPN_QR(2, 6, 10, 14);
        HVPN_QR(3, 7, 11, 15);
        HVPN_QR(0, 5, 10, 15);
        HVPN_QR(1, 6, 11, 12);
        HVPN_QR(2, 7, 8, 13);
        HVPN_QR(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) hvpn_st32(out + i * 4, x[i] + st[i]);
}

// ---------------------------------------------------------------- Poly1305

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t buf_len;
} hvpn_poly1305_ctx;

static void hvpn_poly1305_init(hvpn_poly1305_ctx *c, const uint8_t key[32]) {
    c->r[0] = hvpn_ld32(key + 0) & 0x3ffffff;
    c->r[1] = (hvpn_ld32(key + 3) >> 2) & 0x3ffff03;
    c->r[2] = (hvpn_ld32(key + 6) >> 4) & 0x3ffc0ff;
    c->r[3] = (hvpn_ld32(key + 9) >> 6) & 0x3f03fff;
    c->r[4] = (hvpn_ld32(key + 12) >> 8) & 0x00fffff;
    c->pad[0] = hvpn_ld32(key + 16);
    c->pad[1] = hvpn_ld32(key + 20);
    c->pad[2] = hvpn_ld32(key + 24);
    c->pad[3] = hvpn_ld32(key + 28);
    memset(c->h, 0, sizeof(c->h));
    memset(c->buf, 0, sizeof(c->buf));
    c->buf_len = 0;
}

static void hvpn_poly1305_blocks(hvpn_poly1305_ctx *c, const uint8_t *m, size_t bytes, uint32_t hibit) {
    const uint64_t r0 = c->r[0], r1 = c->r[1], r2 = c->r[2], r3 = c->r[3], r4 = c->r[4];
    const uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint64_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4];

    while (bytes >= 16) {
        uint64_t cbit;

        h0 += hvpn_ld32(m + 0) & 0x3ffffff;
        h1 += (hvpn_ld32(m + 3) >> 2) & 0x3ffffff;
        h2 += (hvpn_ld32(m + 6) >> 4) & 0x3ffffff;
        h3 += (hvpn_ld32(m + 9) >> 6) & 0x3ffffff;
        h4 += (hvpn_ld32(m + 12) >> 8) | hibit;

        uint64_t d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        uint64_t d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        cbit = d0 >> 26; h0 = d0 & 0x3ffffff;
        d1 += cbit; cbit = d1 >> 26; h1 = d1 & 0x3ffffff;
        d2 += cbit; cbit = d2 >> 26; h2 = d2 & 0x3ffffff;
        d3 += cbit; cbit = d3 >> 26; h3 = d3 & 0x3ffffff;
        d4 += cbit; cbit = d4 >> 26; h4 = d4 & 0x3ffffff;
        h0 += cbit * 5; cbit = h0 >> 26; h0 &= 0x3ffffff;
        h1 += cbit;

        m += 16;
        bytes -= 16;
    }

    c->h[0] = (uint32_t)h0;
    c->h[1] = (uint32_t)h1;
    c->h[2] = (uint32_t)h2;
    c->h[3] = (uint32_t)h3;
    c->h[4] = (uint32_t)h4;
}

static void hvpn_poly1305_update(hvpn_poly1305_ctx *c, const uint8_t *m, size_t bytes) {
    if (c->buf_len) {
        size_t need = 16 - c->buf_len;
        if (need > bytes) need = bytes;
        memcpy(c->buf + c->buf_len, m, need);
        c->buf_len += need;
        m += need;
        bytes -= need;
        if (c->buf_len == 16) {
            hvpn_poly1305_blocks(c, c->buf, 16, 1u << 24);
            c->buf_len = 0;
        }
    }
    size_t full = bytes & ~(size_t)15;
    if (full) {
        hvpn_poly1305_blocks(c, m, full, 1u << 24);
        m += full;
        bytes -= full;
    }
    if (bytes) {
        memcpy(c->buf, m, bytes);
        c->buf_len = bytes;
    }
}

static void hvpn_poly1305_finish(hvpn_poly1305_ctx *c, uint8_t mac[16]) {
    if (c->buf_len) {
        c->buf[c->buf_len] = 1;
        memset(c->buf + c->buf_len + 1, 0, 16 - c->buf_len - 1);
        hvpn_poly1305_blocks(c, c->buf, 16, 0);
    }

    uint64_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4];
    uint64_t cbit;

    cbit = h1 >> 26; h1 &= 0x3ffffff; h2 += cbit;
    cbit = h2 >> 26; h2 &= 0x3ffffff; h3 += cbit;
    cbit = h3 >> 26; h3 &= 0x3ffffff; h4 += cbit;
    cbit = h4 >> 26; h4 &= 0x3ffffff; h0 += cbit * 5;
    cbit = h0 >> 26; h0 &= 0x3ffffff; h1 += cbit;

    uint64_t g0 = h0 + 5;
    cbit = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + cbit;
    cbit = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + cbit;
    cbit = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + cbit;
    cbit = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + cbit - (1ULL << 26);

    uint64_t mask = (g4 >> 63) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    uint64_t f = h0 + c->pad[0];            h0 = f & 0xffffffff;
    f = h1 + c->pad[1] + (f >> 32);         h1 = f & 0xffffffff;
    f = h2 + c->pad[2] + (f >> 32);         h2 = f & 0xffffffff;
    f = h3 + c->pad[3] + (f >> 32);         h3 = f & 0xffffffff;

    hvpn_st32(mac + 0, (uint32_t)h0);
    hvpn_st32(mac + 4, (uint32_t)h1);
    hvpn_st32(mac + 8, (uint32_t)h2);
    hvpn_st32(mac + 12, (uint32_t)h3);
}

// ---------------------------------------------------------------- AEAD

static int hvpn_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0 ? 0 : -1;
}

int HVPNChaCha20Poly1305Decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *in, size_t inLen, uint8_t *out) {
    if (inLen < 16) return -1;

    const size_t ctLen = inLen - 16;
    uint8_t block0[64];
    hvpn_chacha20_block(key, 0, nonce, block0);

    hvpn_poly1305_ctx ctx;
    hvpn_poly1305_init(&ctx, block0);
    if (ctLen) hvpn_poly1305_update(&ctx, in, ctLen);
    if (ctLen % 16) {
        static const uint8_t zeros[16];
        hvpn_poly1305_update(&ctx, zeros, 16 - (ctLen % 16));
    }
    uint8_t lens[16];
    hvpn_st64(lens + 0, 0);          // AAD пустой
    hvpn_st64(lens + 8, (uint64_t)ctLen);
    hvpn_poly1305_update(&ctx, lens, sizeof(lens));

    uint8_t mac[16];
    hvpn_poly1305_finish(&ctx, mac);
    if (hvpn_ct_equal(mac, in + ctLen, 16) != 0) return -1;

    uint8_t ks[64];
    size_t off = 0;
    uint32_t counter = 1;
    while (off < ctLen) {
        hvpn_chacha20_block(key, counter++, nonce, ks);
        size_t n = ctLen - off;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        off += n;
    }
    return 0;
}
