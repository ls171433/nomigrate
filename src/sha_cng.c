#include <nomigrate/openssl/sha.h>

int NOMIGRATE_ITEM_L(SHA1_Init)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&ctx->core.h_cng_alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    status = BCryptCreateHash(ctx->core.h_cng_alg, &ctx->core.h_cng_hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA1_Update)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx, const void *data, size_t data_size)
{
    NTSTATUS status;

    status = BCryptHashData(ctx->core.h_cng_hash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA1_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA1_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptFinishHash(ctx->core.h_cng_hash, out_data, NOMIGRATE_ITEM_U(SHA1_DIGEST_LENGTH), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA256_Init)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&ctx->core.h_cng_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    status = BCryptCreateHash(ctx->core.h_cng_alg, &ctx->core.h_cng_hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA256_Update)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx, const void *data, size_t data_size)
{
    NTSTATUS status;

    status = BCryptHashData(ctx->core.h_cng_hash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA256_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA256_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptFinishHash(ctx->core.h_cng_hash, out_data, NOMIGRATE_ITEM_U(SHA256_DIGEST_LENGTH), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA384_Init)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&ctx->core.h_cng_alg, BCRYPT_SHA384_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    status = BCryptCreateHash(ctx->core.h_cng_alg, &ctx->core.h_cng_hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA384_Update)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx, const void *data, size_t data_size)
{
    NTSTATUS status;

    status = BCryptHashData(ctx->core.h_cng_hash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA384_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA384_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptFinishHash(ctx->core.h_cng_hash, out_data, NOMIGRATE_ITEM_U(SHA384_DIGEST_LENGTH), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA512_Init)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&ctx->core.h_cng_alg, BCRYPT_SHA512_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    status = BCryptCreateHash(ctx->core.h_cng_alg, &ctx->core.h_cng_hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA512_Update)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx, const void *data, size_t data_size)
{
    NTSTATUS status;

    status = BCryptHashData(ctx->core.h_cng_hash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}

int NOMIGRATE_ITEM_L(SHA512_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA512_CTX) *ctx)
{
    NTSTATUS status;

    status = BCryptFinishHash(ctx->core.h_cng_hash, out_data, NOMIGRATE_ITEM_U(SHA512_DIGEST_LENGTH), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(ctx->core.h_cng_alg, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return 0;
    }

    return 1;
}
