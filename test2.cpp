#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

std::string to_hex(unsigned char* str, int len) {
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
            result.push_back(chars[carry % 58];
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

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* prv = BN_new();
    BN_hex2bn(&prv, hex_private_key.c_str());
    EC_KEY_set_private_key(key, prv);

    // Generate public key
    EC_POINT* pub = EC_POINT_new(EC_KEY_get0_group(key));
    EC_POINT_mul(EC_KEY_get0_group(key), pub, prv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pub);

    // Get public key data
    unsigned char pub_key[65];
    EC_POINT_point2oct(EC_KEY_get0_group(key), pub, POINT_CONVERSION_UNCOMPRESSED, pub_key, 65, NULL);

    // SHA-256
    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    SHA256(pub_key, sizeof(pub_key), sha256_result);

    // RIPEMD-160
    unsigned char ripemd_result[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_result, SHA256_DIGEST_LENGTH, ripemd_result);

    // Base58Check Encoding
    std::vector<unsigned char> address_data(ripemd_result, ripemd_result + RIPEMD160_DIGEST_LENGTH);
    address_data.insert(address_data.begin(), 0x00); // Version byte: 0x00 for Bitcoin mainnet
    std::string btc_address = base58_encode(address_data);

    std::cout << "Bitcoin Address: " << btc_address << std::endl;

    // Cleanup
    EC_KEY_free(key);
    BN_free(prv);
    EC_POINT_free(pub);

    return 0;
}
