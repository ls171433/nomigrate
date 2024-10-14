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
    EXPECT_EQ(sizeof(NOMIGRATE_SHA_CTX),    sizeof(SHA_CTX));
    EXPECT_EQ(sizeof(NOMIGRATE_SHA256_CTX), sizeof(SHA256_CTX));
    EXPECT_EQ(sizeof(NOMIGRATE_SHA512_CTX), sizeof(SHA512_CTX));

    EXPECT_EQ(NOMIGRATE_SHA_DIGEST_LENGTH,        SHA_DIGEST_LENGTH);
    EXPECT_EQ(NOMIGRATE_SHA256_192_DIGEST_LENGTH, SHA256_192_DIGEST_LENGTH);
    EXPECT_EQ(NOMIGRATE_SHA224_DIGEST_LENGTH,     SHA224_DIGEST_LENGTH);
    EXPECT_EQ(NOMIGRATE_SHA256_DIGEST_LENGTH,     SHA256_DIGEST_LENGTH);
    EXPECT_EQ(NOMIGRATE_SHA384_DIGEST_LENGTH,     SHA384_DIGEST_LENGTH);
    EXPECT_EQ(NOMIGRATE_SHA512_DIGEST_LENGTH,     SHA512_DIGEST_LENGTH);
}

TEST(sha, SHA1)
{
    NOMIGRATE_SHA_CTX nomigrate_ctx;
              SHA_CTX  original_ctx;
    EXPECT_TRUE(nomigrate_SHA1_Init(&nomigrate_ctx));
    EXPECT_TRUE(          SHA1_Init( &original_ctx));

    for (size_t i = 0; i < random_int<size_t>(0, 10000); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 65536));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        EXPECT_TRUE(nomigrate_SHA1_Update(&nomigrate_ctx, buffer.data(), buffer.size()));
        EXPECT_TRUE(          SHA1_Update( &original_ctx, buffer.data(), buffer.size()));
    }

    std::vector<unsigned char> nomigrate_hash(SHA_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA_DIGEST_LENGTH);

    EXPECT_TRUE(nomigrate_SHA1_Final(nomigrate_hash.data(), &nomigrate_ctx));
    EXPECT_TRUE(          SHA1_Final( original_hash.data(),  &original_ctx));

    EXPECT_EQ(nomigrate_hash, original_hash);
}

#if 0
TEST(sha, SHA224)
{
    NOMIGRATE_SHA256_CTX nomigrate_ctx;
              SHA256_CTX  original_ctx;
    EXPECT_TRUE(nomigrate_SHA224_Init(&nomigrate_ctx));
    EXPECT_TRUE(          SHA224_Init( &original_ctx));

    for (size_t i = 0; i < random_int<size_t>(0, 10000); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 65536));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        EXPECT_TRUE(nomigrate_SHA224_Update(&nomigrate_ctx, buffer.data(), buffer.size()));
        EXPECT_TRUE(          SHA224_Update( &original_ctx, buffer.data(), buffer.size()));
    }

    std::vector<unsigned char> nomigrate_hash(SHA224_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA224_DIGEST_LENGTH);

    EXPECT_TRUE(nomigrate_SHA224_Final(nomigrate_hash.data(), &nomigrate_ctx));
    EXPECT_TRUE(          SHA224_Final( original_hash.data(),  &original_ctx));

    EXPECT_EQ(nomigrate_hash, original_hash);
}
#endif

TEST(sha, SHA256)
{
    NOMIGRATE_SHA256_CTX nomigrate_ctx;
              SHA256_CTX  original_ctx;
    EXPECT_TRUE(nomigrate_SHA256_Init(&nomigrate_ctx));
    EXPECT_TRUE(          SHA256_Init( &original_ctx));

    for (size_t i = 0; i < random_int<size_t>(0, 10000); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 65536));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        EXPECT_TRUE(nomigrate_SHA256_Update(&nomigrate_ctx, buffer.data(), buffer.size()));
        EXPECT_TRUE(          SHA256_Update( &original_ctx, buffer.data(), buffer.size()));
    }

    std::vector<unsigned char> nomigrate_hash(SHA256_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA256_DIGEST_LENGTH);

    EXPECT_TRUE(nomigrate_SHA256_Final(nomigrate_hash.data(), &nomigrate_ctx));
    EXPECT_TRUE(          SHA256_Final( original_hash.data(),  &original_ctx));

    EXPECT_EQ(nomigrate_hash, original_hash);
}

TEST(sha, SHA384)
{
    NOMIGRATE_SHA512_CTX nomigrate_ctx;
              SHA512_CTX  original_ctx;
    EXPECT_TRUE(nomigrate_SHA384_Init(&nomigrate_ctx));
    EXPECT_TRUE(          SHA384_Init( &original_ctx));

    for (size_t i = 0; i < random_int<size_t>(0, 10000); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 65536));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        EXPECT_TRUE(nomigrate_SHA384_Update(&nomigrate_ctx, buffer.data(), buffer.size()));
        EXPECT_TRUE(          SHA384_Update( &original_ctx, buffer.data(), buffer.size()));
    }

    std::vector<unsigned char> nomigrate_hash(SHA384_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA384_DIGEST_LENGTH);

    EXPECT_TRUE(nomigrate_SHA384_Final(nomigrate_hash.data(), &nomigrate_ctx));
    EXPECT_TRUE(          SHA384_Final( original_hash.data(),  &original_ctx));

    EXPECT_EQ(nomigrate_hash, original_hash);
}

TEST(sha, SHA512)
{
    NOMIGRATE_SHA512_CTX nomigrate_ctx;
              SHA512_CTX  original_ctx;
    EXPECT_TRUE(nomigrate_SHA512_Init(&nomigrate_ctx));
    EXPECT_TRUE(          SHA512_Init( &original_ctx));

    for (size_t i = 0; i < random_int<size_t>(0, 10000); ++i)
    {
        std::vector<unsigned char> buffer(random_int<size_t>(0, 65536));
        for (unsigned char& c : buffer)
        {
            c = random_int<unsigned char>(0, UCHAR_MAX);
        }
        EXPECT_TRUE(nomigrate_SHA512_Update(&nomigrate_ctx, buffer.data(), buffer.size()));
        EXPECT_TRUE(          SHA512_Update( &original_ctx, buffer.data(), buffer.size()));
    }

    std::vector<unsigned char> nomigrate_hash(SHA512_DIGEST_LENGTH);
    std::vector<unsigned char>  original_hash(SHA512_DIGEST_LENGTH);

    EXPECT_TRUE(nomigrate_SHA512_Final(nomigrate_hash.data(), &nomigrate_ctx));
    EXPECT_TRUE(          SHA512_Final( original_hash.data(),  &original_ctx));

    EXPECT_EQ(nomigrate_hash, original_hash);
}
