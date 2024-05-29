#include <iostream>
#include <bitset>
#include <vector>
#include <string>
#include <gmp.h>
#include <chrono>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <algorithm>

// Fungsi untuk mengonversi integer ke string biner 6-bit
std::string intToBinary6(int num) {
    std::bitset<6> bin(num);
    return bin.to_string();
}

// Fungsi untuk menghasilkan semua kombinasi biner 6-bit
std::vector<std::string> generateAllCombinations() {
    std::vector<std::string> allCombinations;
    for (int i = 0; i < 64; ++i) {
        allCombinations.push_back(intToBinary6(i));
    }
    return allCombinations;
}

// Fungsi konversi dari biner ke heksadesimal
std::string binaryToHex(const std::string &binaryStr) {
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, binaryStr.c_str(), 2);  // Set num to the value of binaryStr interpreted as a binary number
    char* hex_cstr = mpz_get_str(NULL, 16, num);  // Convert num to a hexadecimal string
    std::string hex_str(hex_cstr);
    free(hex_cstr);
    mpz_clear(num);
    return hex_str;
}

// Fungsi tambahan untuk konversi hex ke BTC address
void hexToBytes(const std::string& hex, std::vector<unsigned char>& bytes) {
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
}

std::string toBase58Check(const std::vector<unsigned char>& data) {
    const char* base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    unsigned char sha256Digest1[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256Digest1);
    unsigned char sha256Digest2[SHA256_DIGEST_LENGTH];
    SHA256(sha256Digest1, SHA256_DIGEST_LENGTH, sha256Digest2);

    std::vector<unsigned char> extendedData(data);
    extendedData.insert(extendedData.end(), sha256Digest2, sha256Digest2 + 4);

    std::vector<unsigned char> base58Encoded;
    base58Encoded.reserve(extendedData.size() * 138 / 100 + 1);

    BIGNUM* bnData = BN_new();
    BIGNUM* bnBase = BN_new();
    BIGNUM* bnMod = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_bin2bn(extendedData.data(), extendedData.size(), bnData);
    BN_set_word(bnBase, 58);

    while (!BN_is_zero(bnData)) {
        BN_div(bnData, bnMod, bnData, bnBase, ctx);
        unsigned int mod = BN_get_word(bnMod);
        base58Encoded.push_back(base58Chars[mod]);
    }

    BN_free(bnData);
    BN_free(bnBase);
    BN_free(bnMod);
    BN_CTX_free(ctx);

    std::reverse(base58Encoded.begin(), base58Encoded.end());

    for (unsigned char byte : data) {
        if (byte != 0) break;
        base58Encoded.insert(base58Encoded.begin(), '1');
    }

    return std::string(base58Encoded.begin(), base58Encoded.end());
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <number_of_patterns>" << std::endl;
        return 1;
    }

    int numPatterns = std::atoi(argv[1]);
    if (numPatterns <= 0) {
        std::cerr << "Number of patterns must be positive." << std::endl;
        return 1;
    }

    std::vector<std::string> allCombinations = generateAllCombinations();

    mpz_t totalCombinations;
    mpz_init(totalCombinations);
    mpz_ui_pow_ui(totalCombinations, 64, numPatterns);  // 64^numPatterns

    gmp_printf("Total kombinasi yang mungkin: %Zd\n", totalCombinations);

    // Start time measurement
    auto start = std::chrono::steady_clock::now();

    mpz_t i;
    mpz_init_set_ui(i, 0);
    unsigned long count = 0;
    while(mpz_cmp(i, totalCombinations) < 0) {  // Iterate through all combinations
        unsigned long long combination = mpz_get_ui(i);
        std::string result;
        for (int j = 0; j < numPatterns; ++j) {
            int index = (combination >> (6 * j)) & 0x3F;
            result += allCombinations[index];
        }
        std::string hexResult = binaryToHex(result);

        // Debugging output
        std::cout << "Hex result: " << hexResult << std::endl;

        // Mengubah hexResult menjadi BTC address terkompresi
        std::vector<unsigned char> privKey;
        hexToBytes(hexResult, privKey);

        if (privKey.size() != 32) {
            std::cerr << "Invalid private key length: " << privKey.size() << std::endl;
            mpz_add_ui(i, i, 1);
            continue;
        }

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data())) {
            std::cerr << "Failed to create public key" << std::endl;
            secp256k1_context_destroy(ctx);
            mpz_add_ui(i, i, 1);
            continue;
        }

        unsigned char pubkeyCompressed[33];
        size_t outputLength = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkeyCompressed, &outputLength, &pubkey, SECP256K1_EC_COMPRESSED);

        unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
        SHA256(pubkeyCompressed, 33, sha256Digest);

        unsigned char ripemd160Digest[RIPEMD160_DIGEST_LENGTH];
        RIPEMD160(sha256Digest, SHA256_DIGEST_LENGTH, ripemd160Digest);

        std::vector<unsigned char> extendedRipemd160(21);
        extendedRipemd160[0] = 0x00;
        std::copy(ripemd160Digest, ripemd160Digest + RIPEMD160_DIGEST_LENGTH, extendedRipemd160.begin() + 1);

        std::string btcAddress = toBase58Check(extendedRipemd160);

        std::cout << "BTC Address: " << btcAddress << std::endl;

        secp256k1_context_destroy(ctx);

        mpz_add_ui(i, i, 1);
        count++;
    }

    // End time measurement
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::cout << "Elapsed time: " << elapsed_seconds.count() << "s\n";

    mpz_clear(totalCombinations);
    mpz_clear(i);

    return 0;
}
