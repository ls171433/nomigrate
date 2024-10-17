#include <nomigrate/openssl/sha.h>

void NOMIGRATE_ITEM_L(SHA1_Transform)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx, const unsigned char *data)
{
}

void NOMIGRATE_ITEM_L(SHA224_Transform)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx, const unsigned char *data)
{
}

void NOMIGRATE_ITEM_L(SHA256_Transform)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx, const unsigned char *data)
{
}

void NOMIGRATE_ITEM_L(SHA384_Transform)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx, const unsigned char *data)
{
}

void NOMIGRATE_ITEM_L(SHA512_Transform)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx, const unsigned char *data)
{
}

unsigned char *NOMIGRATE_ITEM_L(SHA1)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA1_CTX) ctx;
    static unsigned char static_out_data[NOMIGRATE_ITEM_U(SHA1_DIGEST_LENGTH)];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

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

unsigned char *NOMIGRATE_ITEM_L(SHA224)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA224_CTX) ctx;
    static unsigned char static_out_data[NOMIGRATE_ITEM_U(SHA224_DIGEST_LENGTH)];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    if (!NOMIGRATE_ITEM_L(SHA224_Init)(&ctx))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA224_Update)(&ctx, data, data_size))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA224_Final)(out_data, &ctx))
    {
        return NULL;
    }

    return out_data;
}

unsigned char *NOMIGRATE_ITEM_L(SHA256)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA256_CTX) ctx;
    static unsigned char static_out_data[NOMIGRATE_ITEM_U(SHA256_DIGEST_LENGTH)];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    if (!NOMIGRATE_ITEM_L(SHA256_Init)(&ctx))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA256_Update)(&ctx, data, data_size))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA256_Final)(out_data, &ctx))
    {
        return NULL;
    }

    return out_data;
}

unsigned char *NOMIGRATE_ITEM_L(SHA384)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA384_CTX) ctx;
    static unsigned char static_out_data[NOMIGRATE_ITEM_U(SHA384_DIGEST_LENGTH)];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    if (!NOMIGRATE_ITEM_L(SHA384_Init)(&ctx))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA384_Update)(&ctx, data, data_size))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA384_Final)(out_data, &ctx))
    {
        return NULL;
    }

    return out_data;
}

unsigned char *NOMIGRATE_ITEM_L(SHA512)(const unsigned char *data, size_t data_size, unsigned char *out_data)
{
    NOMIGRATE_ITEM_U(SHA512_CTX) ctx;
    static unsigned char static_out_data[NOMIGRATE_ITEM_U(SHA512_DIGEST_LENGTH)];

    if (out_data == NULL)
    {
        out_data = static_out_data;
    }

    if (!NOMIGRATE_ITEM_L(SHA512_Init)(&ctx))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA512_Update)(&ctx, data, data_size))
    {
        return NULL;
    }

    if (!NOMIGRATE_ITEM_L(SHA512_Final)(out_data, &ctx))
    {
        return NULL;
    }

    return out_data;
}
