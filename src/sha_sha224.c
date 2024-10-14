#include <nomigrate/openssl/sha.h>

int NOMIGRATE_ITEM_L(SHA224_Init)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx)
{
    return 0;
}

int NOMIGRATE_ITEM_L(SHA224_Update)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx, const void *data, size_t data_size)
{
    return 0;
}

int NOMIGRATE_ITEM_L(SHA224_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA224_CTX) *ctx)
{
    return 0;
}
