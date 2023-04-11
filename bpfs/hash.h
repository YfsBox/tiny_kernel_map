//
// Created by 杨丰硕 on 2023/4/9.
//

#ifndef KERNEL_MAP_HASH_H
#define KERNEL_MAP_HASH_H

#define SHA256_SIZE_BYTES  (32)

#define FN_ static __always_inline

typedef unsigned int hash_uint32_t;
typedef unsigned char hash_uint8_t;

struct sha256_context {
    hash_uint8_t  buf[64];
    hash_uint32_t hash[8];
    hash_uint32_t bits[2];
    hash_uint32_t len;
    hash_uint32_t rfu__;
    hash_uint32_t W[64];
};

struct hash_msg_buffer {
    hash_uint8_t buffer_[SHA256_SIZE_BYTES];
};

static const unsigned int K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// -----------------------------------------------------------------------------
FN_ hash_uint8_t _shb(hash_uint32_t x, hash_uint32_t n) {
    return ((x >> (n & 31)) & 0xff);
} // _shb

// -----------------------------------------------------------------------------
FN_ hash_uint32_t _shw(hash_uint32_t x, hash_uint32_t n) {
    return ((x << (n & 31)) & 0xffffffff);
} // _shw


// -----------------------------------------------------------------------------
FN_ hash_uint32_t _r(hash_uint32_t x, hash_uint8_t n) {
    return ((x >> n) | _shw(x, 32 - n));
} // _r

// -----------------------------------------------------------------------------
FN_ hash_uint32_t _Ch(hash_uint32_t x, hash_uint32_t y, hash_uint32_t z) {
    return ((x & y) ^ ((~x) & z));
} // _Ch

// -----------------------------------------------------------------------------
FN_ hash_uint32_t _Ma(hash_uint32_t x, hash_uint32_t y, hash_uint32_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
} // _Ma


// -----------------------------------------------------------------------------
FN_ hash_uint32_t _S0(hash_uint32_t x) {
    return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
} // _S0


// -----------------------------------------------------------------------------
FN_ hash_uint32_t _S1(hash_uint32_t x) {
    return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
} // _S1


// -----------------------------------------------------------------------------
FN_ hash_uint32_t _G0(hash_uint32_t x) {
    return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
} // _G0

// -----------------------------------------------------------------------------
FN_ hash_uint32_t _G1(hash_uint32_t x) {
    return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
} // _G1

// -----------------------------------------------------------------------------
FN_ hash_uint32_t _word(hash_uint8_t *c) {
    return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
} // _word


// -----------------------------------------------------------------------------
static void _addbits(struct sha256_context *ctx, hash_uint32_t n) {
    if (ctx->bits[0] > (0xffffffff - n)) {
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    }
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} // _addbits


// -----------------------------------------------------------------------------
static void _hash(struct sha256_context *ctx) {
    register hash_uint32_t a, b, c, d, e, f, g, h;
    hash_uint32_t t[2];

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    for (hash_uint32_t i = 0; i < 64; i++) {
        if (i < 16) {
            ctx->W[i] = _word(&ctx->buf[_shw(i, 2)]);
        } else {
            ctx->W[i] = _G1(ctx->W[i - 2])  + ctx->W[i - 7] +
                        _G0(ctx->W[i - 15]) + ctx->W[i - 16];
        }

        t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + ctx->W[i];
        t[1] = _S0(a) + _Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
} // _hash


// -----------------------------------------------------------------------------
void sha256_init(struct sha256_context *ctx) {
    if (ctx) {
        ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
        ctx->hash[0] = 0x6a09e667;
        ctx->hash[1] = 0xbb67ae85;
        ctx->hash[2] = 0x3c6ef372;
        ctx->hash[3] = 0xa54ff53a;
        ctx->hash[4] = 0x510e527f;
        ctx->hash[5] = 0x9b05688c;
        ctx->hash[6] = 0x1f83d9ab;
        ctx->hash[7] = 0x5be0cd19;
    }
} // sha256_init


// -----------------------------------------------------------------------------
FN_ int sha256_hash(struct sha256_context *ctx, const void *data, unsigned len) {
    const hash_uint8_t *bytes = (const hash_uint8_t *)data;

    if (ctx && bytes && (ctx->len < sizeof(ctx->buf))) {
        for (unsigned i = 0; i < len; i++) {
            ctx->buf[ctx->len++] = bytes[i];
            if (ctx->len == sizeof(ctx->buf)) {
                _hash(ctx);
                _addbits(ctx, sizeof(ctx->buf) * 8);
                ctx->len = 0;
            }
        }
    }
    return 0;
} // sha256_hash


// -----------------------------------------------------------------------------
FN_ int sha256_done(struct sha256_context *ctx, hash_uint8_t *hash) {
    register hash_uint32_t i, j;

    if (ctx) {
        j = ctx->len % sizeof(ctx->buf);
        ctx->buf[j] = 0x80;
        volatile hash_uint8_t *bufptr = ctx->buf;
        for (i = j + 1; i < sizeof(ctx->buf); i++) {
            bufptr[i] = 0x00;
        }

        if (ctx->len > 55) {
            _hash(ctx);
            for (j = 0; j < sizeof(ctx->buf); j++) {
                bufptr[j] = 0x00;
            }
        }

        _addbits(ctx, ctx->len * 8);
        ctx->buf[63] = _shb(ctx->bits[0],  0);
        ctx->buf[62] = _shb(ctx->bits[0],  8);
        ctx->buf[61] = _shb(ctx->bits[0], 16);
        ctx->buf[60] = _shb(ctx->bits[0], 24);
        ctx->buf[59] = _shb(ctx->bits[1],  0);
        ctx->buf[58] = _shb(ctx->bits[1],  8);
        ctx->buf[57] = _shb(ctx->bits[1], 16);
        ctx->buf[56] = _shb(ctx->bits[1], 24);
        _hash(ctx);

        if (hash) {
            for (i = 0, j = 24; i < 4; i++, j -= 8) {
                hash[i +  0] = _shb(ctx->hash[0], j);
                hash[i +  4] = _shb(ctx->hash[1], j);
                hash[i +  8] = _shb(ctx->hash[2], j);
                hash[i + 12] = _shb(ctx->hash[3], j);
                hash[i + 16] = _shb(ctx->hash[4], j);
                hash[i + 20] = _shb(ctx->hash[5], j);
                hash[i + 24] = _shb(ctx->hash[6], j);
                hash[i + 28] = _shb(ctx->hash[7], j);
            }
        }
    }
    return 0;
} // sha256_done

// -----------------------------------------------------------------------------
FN_ int sha256(const void *data, unsigned len, hash_uint8_t *hash) {
    struct sha256_context ctx;

    sha256_init(&ctx);
    sha256_hash(&ctx, data, len);
    // sha256_done(&ctx, hash);
    return 0;
} // sha256

#endif //KERNEL_MAP_HASH_H
