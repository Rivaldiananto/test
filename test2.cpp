#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

std::string to_hex(const unsigned char* str, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)str[i];
    return ss.str();
}

std::string base58_encode(const std::vector<unsigned char>& data) {
    // Implementasi sederhana dari Base58
    const char* chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string result;
    // Langkah encode Base58 disederhanakan untuk demonstrasi
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

    // Mengambil hexadecimal private key dari argumen baris perintah
    std::string hex_private_key = argv[1];
    const char* curve_name = "secp256k1";

    // Setup
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, OBJ_sn2nid(curve_name));
    EVP_PKEY* params = NULL;
    EVP_PKEY_paramgen(pctx, &params);
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    
    // Generate key
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen(kctx, &pkey);

    // Derive public key
    unsigned char* pub_key;
    size_t pub_key_len;
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_key_len);
    pub_key = (unsigned char*)OPENSSL_malloc(pub_key_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_key_len);

    // SHA-256
    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    SHA256(pub_key, pub_key_len, sha256_result);

    // RIPEMD-160
    unsigned char ripemd_result[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_result, SHA256_DIGEST_LENGTH, ripemd_result);

    // Base58Check Encoding
    std::vector<unsigned char> address_data(ripemd_result, ripemd_result + RIPEMD160_DIGEST_LENGTH);
    address_data.insert(address_data.begin(), 0x00); // Version byte: 0x00 for Bitcoin mainnet
    std::string btc_address = base58_encode(address_data);

    std::cout << "Bitcoin Address: " << btc_address << std::endl;

    // Cleanup
    OPENSSL_free(pub_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);

    return 0;
}
