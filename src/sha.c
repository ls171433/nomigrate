#include <nomigrate/openssl/sha.h>

int SHA1_Init(SHA_CTX *ctx)
{
    BCryptOpenAlgorithmProvider(&(ctx->h_alg), BCRYPT_SHA1_ALGORITHM, NULL, 0);
    BCryptCreateHash(ctx->h_alg, &(ctx->h_hash), NULL, 0, NULL, 0, 0);

    return 0;
}

int SHA1_Update(SHA_CTX *ctx, const void *data, size_t data_size)
{
    BCryptHashData(ctx->h_hash, (PUCHAR)data, data_size, 0);

    return 0;
}

int SHA1_Final(unsigned char *out_data, SHA_CTX *ctx)
{
    static unsigned char static_out_data[SHA_DIGEST_LENGTH];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    BCryptFinishHash(ctx->h_hash, out_data, SHA_DIGEST_LENGTH, 0);
    BCryptCloseAlgorithmProvider(ctx->h_alg, 0);

    return 0;
}

void SHA1_Transform(SHA_CTX *ctx, const unsigned char *data)
{
}

unsigned char *SHA1(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, data_size);
    SHA1_Final(out_data, &ctx);
    return out_data;
}
