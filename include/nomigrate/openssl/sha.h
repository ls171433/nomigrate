#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_DIGEST_LENGTH 20

struct SHA_CTX_ST {
    BCRYPT_ALG_HANDLE h_alg;
    BCRYPT_HASH_HANDLE h_hash;
};

typedef struct SHA_CTX_ST SHA_CTX;

int SHA1_Init(SHA_CTX *ctx);
int SHA1_Update(SHA_CTX *ctx, const void *data, size_t data_size);
int SHA1_Final(unsigned char *out_data, SHA_CTX *ctx);
void SHA1_Transform(SHA_CTX *ctx, const unsigned char *data);

unsigned char *SHA1(const unsigned char *data, size_t data_size, unsigned char *out_data);

#ifdef __cplusplus
}
#endif
