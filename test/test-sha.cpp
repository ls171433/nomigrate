#include <nomigrate/openssl/sha.h>

#include <gtest/gtest.h>
#include <openssl/sha.h>

#include <random>

template <class int_type>
static int_type random_int(int_type min, int_type max)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int_type> dist(min, max);
    return dist(gen);
}

TEST(sha, general)
{
    EXPECT_LE(sizeof(NOMIGRATE_SHA_CTX_CORE), sizeof(SHA_CTX));
    EXPECT_EQ(sizeof(NOMIGRATE_SHA_CTX), sizeof(SHA_CTX));
}

struct together_SHA_CTX
{
    NOMIGRATE_SHA_CTX nomigrate_ctx;
              SHA_CTX  original_ctx;
};

static void together_SHA1_Init(together_SHA_CTX *ctx)
{
    EXPECT_NE(nomigrate_SHA1_Init(&ctx->nomigrate_ctx), 0);
    EXPECT_NE(          SHA1_Init(&ctx-> original_ctx), 0);
}

static void together_SHA1_Update(together_SHA_CTX *ctx, const void *data, size_t data_size)
{
    EXPECT_NE(nomigrate_SHA1_Update(&ctx->nomigrate_ctx, data, data_size), 0);
    EXPECT_NE(          SHA1_Update(&ctx-> original_ctx, data, data_size), 0);
}

static void together_SHA1_Final(together_SHA_CTX *ctx)
{
    std::vector<unsigned char> nomigrate_hash(SHA_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA_DIGEST_LENGTH);

    EXPECT_NE(nomigrate_SHA1_Final(nomigrate_hash.data(), &ctx->nomigrate_ctx), 0);
    EXPECT_NE(          SHA1_Final( original_hash.data(), &ctx-> original_ctx), 0);

    EXPECT_EQ(nomigrate_hash, original_hash);
}

TEST(sha, SHA1)
{
    together_SHA_CTX ctx;
    together_SHA1_Init(&ctx);

    for (size_t i = 0; i < random_int<size_t>(0, 0x0FFF); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 0x0FFF));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        together_SHA1_Update(&ctx, buffer.data(), buffer.size());
    }

    together_SHA1_Final(&ctx);
}
