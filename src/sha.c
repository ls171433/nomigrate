#include <nomigrate/openssl/sha.h>

int NOMIGRATE_ITEM_L(SHA1_Init)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&ctx->core.h_alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    status = BCryptCreateHash(ctx->core.h_alg, &ctx->core.h_hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_alg, 0);
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA1_Update)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx, const void *data, size_t data_size)
{
    NTSTATUS status;

    status = BCryptHashData(ctx->core.h_hash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA1_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA_CTX) *ctx)
{
    NTSTATUS status;
    static unsigned char static_out_data[SHA_DIGEST_LENGTH];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    status = BCryptFinishHash(ctx->core.h_hash, out_data, SHA_DIGEST_LENGTH, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_alg, 0);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(ctx->core.h_alg, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

void NOMIGRATE_ITEM_L(SHA1_Transform)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx, const unsigned char *data)
{
}

unsigned char *NOMIGRATE_ITEM_L(SHA1)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA_CTX) ctx;

    if (!NOMIGRATE_ITEM_L(SHA1_Init)(&ctx))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA1_Update)(&ctx, data, data_size))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA1_Final)(out_data, &ctx))
    {
        return NULL;
    }

    return out_data;
}
