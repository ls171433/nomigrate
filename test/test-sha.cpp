#include <nomigrate/openssl/sha.h>

#include <gtest/gtest.h>

TEST(SHA1, SHA1)
{
    SHA_CTX sha1;
    SHA1_Init(&sha1);

    std::vector<char> buffer(8192);
    SHA1_Update(&sha1, buffer.data(), 0);
    SHA1_Update(&sha1, "1", 1);
    SHA1_Update(&sha1, "1", 1);

    std::vector<unsigned char> hash(SHA_DIGEST_LENGTH);
    SHA1_Final(hash.data(), &sha1);
}
