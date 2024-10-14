#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <stddef.h>
#include <stdint.h>

#ifndef NOMIGRATE_COVER
# define NOMIGRATE_ITEM_L(x) nomigrate_##x
# define NOMIGRATE_ITEM_U(x) NOMIGRATE_##x
#else
# define NOMIGRATE_ITEM_L(x) x
# define NOMIGRATE_ITEM_U(x) x
#endif

#ifndef NOMIGRATE_COVER
# define NOMIGRATE_SHA_DIGEST_LENGTH        20
# define NOMIGRATE_SHA1_DIGEST_LENGTH       20
# define NOMIGRATE_SHA256_192_DIGEST_LENGTH 24
# define NOMIGRATE_SHA224_DIGEST_LENGTH     28
# define NOMIGRATE_SHA256_DIGEST_LENGTH     32
# define NOMIGRATE_SHA384_DIGEST_LENGTH     48
# define NOMIGRATE_SHA512_DIGEST_LENGTH     64
#else
# define SHA_DIGEST_LENGTH        20
# define SHA1_DIGEST_LENGTH       20
# define SHA256_192_DIGEST_LENGTH 24
# define SHA224_DIGEST_LENGTH     28
# define SHA256_DIGEST_LENGTH     32
# define SHA384_DIGEST_LENGTH     48
# define SHA512_DIGEST_LENGTH     64
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) {
    BCRYPT_ALG_HANDLE h_cng_alg;
    BCRYPT_HASH_HANDLE h_cng_hash;
};

struct NOMIGRATE_ITEM_U(SHA224_DATA_ST) {
    uint32_t h[8];
    union
    {
        unsigned char rest_data[64];
        struct
        {
            char unused[56];
            uint64_t data_total_data_size;
        };
    };
    uint64_t total_data_size;
};

struct NOMIGRATE_ITEM_U(SHA_CTX_ST) {
    union {
        struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) core;
        char unused[96];
    };
};

struct NOMIGRATE_ITEM_U(SHA256_CTX_ST) {
    union {
        struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) core;
        struct NOMIGRATE_ITEM_U(SHA224_DATA_ST) sha224_data;
        char unused[112];
    };
};

struct NOMIGRATE_ITEM_U(SHA512_CTX_ST) {
    union {
        struct NOMIGRATE_ITEM_U(SHA_CTX_CORE_ST) core;
        char unused[216];
    };
};

typedef struct NOMIGRATE_ITEM_U(SHA_CTX_ST) NOMIGRATE_ITEM_U(SHA_CTX);
typedef struct NOMIGRATE_ITEM_U(SHA_CTX_ST) NOMIGRATE_ITEM_U(SHA1_CTX);
typedef struct NOMIGRATE_ITEM_U(SHA256_CTX_ST) NOMIGRATE_ITEM_U(SHA224_CTX);
typedef struct NOMIGRATE_ITEM_U(SHA256_CTX_ST) NOMIGRATE_ITEM_U(SHA256_CTX);
typedef struct NOMIGRATE_ITEM_U(SHA512_CTX_ST) NOMIGRATE_ITEM_U(SHA384_CTX);
typedef struct NOMIGRATE_ITEM_U(SHA512_CTX_ST) NOMIGRATE_ITEM_U(SHA512_CTX);

int NOMIGRATE_ITEM_L(SHA1_Init)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA1_Update)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA1_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA1_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA1_Transform)(NOMIGRATE_ITEM_U(SHA1_CTX) *ctx, const unsigned char *data);

int NOMIGRATE_ITEM_L(SHA224_Init)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA224_Update)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA224_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA224_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA224_Transform)(NOMIGRATE_ITEM_U(SHA224_CTX) *ctx, const unsigned char *data);

int NOMIGRATE_ITEM_L(SHA256_Init)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA256_Update)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA256_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA256_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA256_Transform)(NOMIGRATE_ITEM_U(SHA256_CTX) *ctx, const unsigned char *data);

int NOMIGRATE_ITEM_L(SHA384_Init)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA384_Update)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA384_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA384_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA384_Transform)(NOMIGRATE_ITEM_U(SHA384_CTX) *ctx, const unsigned char *data);

int NOMIGRATE_ITEM_L(SHA512_Init)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx);
int NOMIGRATE_ITEM_L(SHA512_Update)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx, const void *data, size_t data_size);
int NOMIGRATE_ITEM_L(SHA512_Final)(unsigned char *out_data, NOMIGRATE_ITEM_U(SHA512_CTX) *ctx);
void NOMIGRATE_ITEM_L(SHA512_Transform)(NOMIGRATE_ITEM_U(SHA512_CTX) *ctx, const unsigned char *data);

unsigned char *NOMIGRATE_ITEM_L(SHA1)(const unsigned char *data, size_t data_size, unsigned char *out_data);
unsigned char *NOMIGRATE_ITEM_L(SHA224)(const unsigned char *data, size_t data_size, unsigned char *out_data);
unsigned char *NOMIGRATE_ITEM_L(SHA256)(const unsigned char *data, size_t data_size, unsigned char *out_data);
unsigned char *NOMIGRATE_ITEM_L(SHA384)(const unsigned char *data, size_t data_size, unsigned char *out_data);
unsigned char *NOMIGRATE_ITEM_L(SHA512)(const unsigned char *data, size_t data_size, unsigned char *out_data);

#ifdef __cplusplus
}
#endif
