#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

std::string base58_encode(const std::vector<unsigned char>& data) {
    const char* chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string result;
    for (auto byte : data) {
        int carry = byte;
        for (auto& c : result) {
            carry += 256 * (c - '1');
            c = chars[carry % 58];
            carry /= 58;
        }
        while (carry) {
            result.push_back(chars[carry % 58]);
            carry /= 58;
        }
    }
    return {result.rbegin(), result.rend()};
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <hex_private_key>" << std::endl;
        return 1;
    }

    // Compute SHA-256
    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256_ctx, argv[1], strlen(argv[1]));
    EVP_DigestFinal_ex(sha256_ctx, sha256_result, NULL);
    EVP_MD_CTX_free(sha256_ctx);

    // Compute RIPEMD-160
    unsigned char ripemd_result[RIPEMD160_DIGEST_LENGTH];
    EVP_MD_CTX* ripemd_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ripemd_ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ripemd_ctx, sha256_result, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ripemd_ctx, ripemd_result, NULL);
    EVP_MD_CTX_free(ripemd_ctx);

    // Base58Check Encoding
    std::vector<unsigned char> address_data(ripemd_result, ripemd_result + RIPEMD160_DIGEST_LENGTH);
    address_data.insert(address_data.begin(), 0x00); // Version byte: 0x00 for Bitcoin mainnet
    std::string btc_address = base58_encode(address_data);

    std::cout << "Bitcoin Address: " << btc_address << std::endl;

    return 0;
}
