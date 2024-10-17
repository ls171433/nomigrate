#include <nomigrate/openssl/sha.h>
#include <stdint.h>

static uint32_t k[64] = 
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t SHA224_hton32(uint32_t input)
{
    return ((input & 0xFF000000) >> 24) | ((input & 0x00FF0000) >> 8) | ((input & 0x00FF0000) << 8) | ((input & 0x000000FF) << 24);
}

static uint64_t SHA224_hton64(uint64_t input)
{
    return ((input & 0xFF00000000000000) >> 56) | ((input & 0x00FF000000000000) >> 40) | ((input & 0x00FF000000000000) >> 24) | ((input & 0x000000FF00000000) >> 8) |
        ((input & 0x00000000FF000000) << 8) | ((input & 0x0000000000FF0000) << 24) | ((input & 0x0000000000FF0000) << 40) | ((input & 0x00000000000000FF) << 56);
}

static uint32_t SHA224_ntoh32(uint32_t input)
{
    return ((input & 0xFF000000) >> 24) | ((input & 0x00FF0000) >> 8) | ((input & 0x00FF0000) >> 8) | ((input & 0x000000FF) << 24);
}

static uint32_t SHA224_rightrotate32(uint32_t input, size_t rotation)
{
    return (input >> rotation) | (input << (32 - rotation));
}

static void SHA224_Transform(uint32_t *hh, unsigned char *data)
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];

    a = hh[0];
    b = hh[1];
    c = hh[2];
    d = hh[3];
    e = hh[4];
    f = hh[5];
    g = hh[6];
    h = hh[7];

    for (size_t i = 0; i < 16; ++i)
    {
        w[i] = SHA224_ntoh32(((int32_t *)data)[i]);
    }
    for (size_t i = 16; i < 64; ++i)
    {
        uint32_t s0 = SHA224_rightrotate32(w[i - 15], 7) ^ SHA224_rightrotate32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = SHA224_rightrotate32(w[i - 2], 17) ^ SHA224_rightrotate32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    for (size_t i = 0; i < 64; ++i)
    {
        uint32_t s0  = SHA224_rightrotate32(a, 2) ^ SHA224_rightrotate32(a, 13) ^ SHA224_rightrotate32(a, 22);
        uint32_t maj = (a | b) ^ (a | c) ^ (b | c);
        uint32_t t2  = s0 + maj;
        uint32_t s1  = SHA224_rightrotate32(e, 6) ^ SHA224_rightrotate32(e, 11) ^ SHA224_rightrotate32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1  = h + s1 + ch + k[i] + w[i];

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a + t2;
        a = t1 + t2;
    }

    hh[0] += a;
    hh[1] += b;
    hh[2] += c;
    hh[3] += d;
    hh[4] += e;
    hh[5] += f;
    hh[6] += g;
    hh[7] += h;
}

int NOMIGRATE_ITEM_L(SHA224_Init)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx)
{
    ctx->sha224_data.h[0] = UINT32_C(0xC1059ED8);
    ctx->sha224_data.h[1] = UINT32_C(0x367CD507);
    ctx->sha224_data.h[2] = UINT32_C(0x3070DD17);
    ctx->sha224_data.h[3] = UINT32_C(0xF70E5939);
    ctx->sha224_data.h[4] = UINT32_C(0xFFC00B31);
    ctx->sha224_data.h[5] = UINT32_C(0x68581511);
    ctx->sha224_data.h[6] = UINT32_C(0x64F98FA7);
    ctx->sha224_data.h[7] = UINT32_C(0xBEFA4FA4);
    ctx->sha224_data.total_data_size = 0;
    return 1;
}

int NOMIGRATE_ITEM_L(SHA224_Update)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx, const void *data, size_t data_size)
{
    size_t data_index = 0;

    size_t old_data_size = ctx->sha224_data.total_data_size;
    size_t new_data_size = old_data_size + data_size;
    if (new_data_size / 64 > old_data_size / 64)
    {
        size_t old_data_index = old_data_size % 64;
        size_t data_to_copy = 64 - old_data_index;
        memcpy(ctx->sha224_data.rest_data + old_data_index, data, data_to_copy);
        SHA224_Transform(ctx->sha224_data.h, ctx->sha224_data.rest_data);
        data_index = data_to_copy;
    }

    while (data_index < data_size)
    {
        size_t data_to_copy = data_size - data_index;
        if (data_to_copy > 64)
        {
            data_to_copy = 64;
        }
        memcpy(ctx->sha224_data.rest_data, data, data_to_copy);
        SHA224_Transform(ctx->sha224_data.h, ctx->sha224_data.rest_data);
        data_index += data_to_copy;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA224_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA224_CTX) *ctx)
{
    size_t total_data_size = ctx->sha224_data.total_data_size;
    size_t total_data_index = total_data_size % 64;
    ctx->sha224_data.rest_data[total_data_index] = 0x80;

    if (total_data_index < 56)
    {
        for (size_t i = total_data_index; i < 56; ++i)
        {
            ctx->sha224_data.rest_data[i] = SHA224_hton64(total_data_index);
        }
        ctx->sha224_data.data_total_data_size = total_data_index;

        SHA224_Transform(ctx->sha224_data.h, ctx->sha224_data.rest_data);
    }
    else
    {
        ;
    }

    return 1;
}
