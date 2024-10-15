#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <stddef.h>

#ifndef NOMIGRATE_COVER
# define NOMIGRATE_ITEM_L(x) nomigrate_##x
# define NOMIGRATE_ITEM_U(x) NOMIGRATE_##x
#else
# define NOMIGRATE_ITEM_L(x) x
# define NOMIGRATE_ITEM_U(x) x
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SHA_DIGEST_LENGTH
# define SHA_DIGEST_LENGTH 20
#endif

struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) {
    BCRYPT_ALG_HANDLE h_alg;
    BCRYPT_HASH_HANDLE h_hash;
};

typedef struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) NOMIGRATE_ITEM_U(SHA_CTX_CORE);

struct NOMIGRATE_ITEM_U(SHA_CTX_ST) {
    NOMIGRATE_ITEM_U(SHA_CTX_CORE) core;
    char unused[80];
};

typedef struct NOMIGRATE_ITEM_U(SHA_CTX_ST) NOMIGRATE_ITEM_U(SHA_CTX);

int NOMIGRATE_ITEM_L(SHA1_Init)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA1_Update)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA1_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA1_Transform)(NOMIGRATE_ITEM_U(SHA_CTX) *ctx, const unsigned char *data);

unsigned char *NOMIGRATE_ITEM_L(SHA1)(const unsigned char *data, size_t data_size, unsigned char *out_data);

#ifdef __cplusplus
}
#endif
