#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <atomic>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <nlopt.hpp>

// Pustaka untuk Base58 encoding perlu ditambahkan atau diimplementasikan
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Fungsi Base58 encoding
std::string base58_encode(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> temp(input.size() * 2);
    std::string result;
    int zero_count = 0;

    for (auto c : input) {
        if (c == 0x00) {
            zero_count++;
        } else {
            break;
        }
    }

    int carry;
    int j = temp.size() - 1;

    for (auto byte : input) {
        carry = byte;
        for (int i = temp.size() - 1; i >= 0; i--) {
            carry += 256 * temp[i];
            temp[i] = carry % 58;
            carry /= 58;
        }
    }

    auto it = temp.begin();
    while (it != temp.end() && *it == 0) {
        it++;
    }

    for (; it != temp.end(); it++) {
        result += BASE58_ALPHABET[*it];
    }

    while (zero_count--) {
        result.insert(result.begin(), '1');
    }

    return result;
}

// Fungsi untuk konversi public key menjadi BTC address
std::string pubkey_to_address(const std::vector<unsigned char>& pubkey) {
    unsigned char sha256_1[SHA256_DIGEST_LENGTH];
    SHA256(pubkey.data(), pubkey.size(), sha256_1);

    unsigned char ripemd160[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_1, SHA256_DIGEST_LENGTH, ripemd160);

    std::vector<unsigned char> hashed_pubkey_with_prefix(1 + RIPEMD160_DIGEST_LENGTH);
    hashed_pubkey_with_prefix[0] = 0x00; // versi mainnet
    std::copy(ripemd160, ripemd160 + RIPEMD160_DIGEST_LENGTH, hashed_pubkey_with_prefix.begin() + 1);

    unsigned char sha256_2[SHA256_DIGEST_LENGTH];
    SHA256(hashed_pubkey_with_prefix.data(), hashed_pubkey_with_prefix.size(), sha256_2);

    unsigned char sha256_3[SHA256_DIGEST_LENGTH];
    SHA256(sha256_2, SHA256_DIGEST_LENGTH, sha256_3);

    hashed_pubkey_with_prefix.insert(hashed_pubkey_with_prefix.end(), sha256_3, sha256_3 + 4);

    std::string address = base58_encode(hashed_pubkey_with_prefix);
    return address;
}

// Fungsi objektif untuk optimasi
double objective_function(const std::vector<double> &x, std::vector<double> &grad, void *total_value_new) {
    double total_value = *reinterpret_cast<double*>(total_value_new);
    double sum_x = 0.0;
    for (auto val : x) {
        sum_x += val;
    }
    return std::abs(sum_x - total_value);
}

// Fungsi utama untuk menemukan solusi
void find_solution(std::unordered_set<std::string>& unique_solutions, std::mutex& solutions_lock, const std::vector<std::string>& target_addresses, std::atomic<bool>& found_event) {
    double total_value_new = 4.7931547296039625;
    std::vector<std::pair<double, double>> bounds = { {2.2, 2.8}, {2.2, 2.8} };

    nlopt::opt opt(nlopt::GN_ORIG_DIRECT, 2);
    std::vector<double> lb = {2.2, 2.2};
    std::vector<double> ub = {2.8, 2.8};
    opt.set_lower_bounds(lb);
    opt.set_upper_bounds(ub);
    opt.set_min_objective(objective_function, &total_value_new);
    opt.set_xtol_rel(1e-10);

    while (!found_event.load()) {
        std::vector<double> x(2);
        double minf;
        nlopt::result result = opt.optimize(x, minf);
        
        if (result == nlopt::SUCCESS) {
            std::vector<boost::multiprecision::cpp_dec_float_50> optimal_values_new;
            for (auto val : x) {
                optimal_values_new.push_back(boost::multiprecision::cpp_dec_float_50(val));
            }

            std::vector<boost::multiprecision::cpp_dec_float_50> adjusted_values;
            for (auto val : optimal_values_new) {
                adjusted_values.push_back(val + boost::multiprecision::cpp_dec_float_50("19.250411886234843"));
            }

            std::vector<boost::multiprecision::cpp_dec_float_50> decimal_values;
            std::vector<std::string> hex_values;

            for (auto val : adjusted_values) {
                boost::multiprecision::cpp_dec_float_50 log_value = boost::multiprecision::log10(val);
                decimal_values.push_back(log_value);
                std::stringstream ss;
                ss << std::hex << std::setprecision(50) << log_value;
                hex_values.push_back(ss.str());
            }

            std::lock_guard<std::mutex> lock(solutions_lock);
            for (const auto& hex_val : hex_values) {
                if (unique_solutions.find(hex_val) == unique_solutions.end()) {
                    unique_solutions.insert(hex_val);

                    std::vector<unsigned char> private_key_bytes(hex_val.begin(), hex_val.end());
                    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
                    EC_KEY_generate_key(eckey);

                    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(eckey);
                    BIGNUM *pub_key_bn = BN_new();
                    EC_POINT_point2bn(EC_KEY_get0_group(eckey), pub_key_point, POINT_CONVERSION_COMPRESSED, pub_key_bn, NULL);
                    std::vector<unsigned char> pub_key(BN_num_bytes(pub_key_bn));
                    BN_bn2bin(pub_key_bn, pub_key.data());

                    std::string btc_address = pubkey_to_address(pub_key);
                    std::cout << "Generated BTC Address: " << btc_address << " for hex value: " << hex_val << std::endl;
                    if (std::find(target_addresses.begin(), target_addresses.end(), btc_address) != target_addresses.end()) {
                        std::cout << "Match found! BTC Address: " << btc_address << " for hex value: " << hex_val << std::endl;
                        found_event.store(true);
                        break;
                    }

                    BN_free(pub_key_bn);
                    EC_KEY_free(eckey);
                }
            }
        } else {
            std::cout << "Optimization was not successful." << std::endl;
            break;
        }
    }
}

int main() {
    std::unordered_set<std::string> unique_solutions;
    std::mutex solutions_lock;
    std::vector<std::string> target_addresses = {"1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN"};
    std::atomic<bool> found_event(false);
    std::vector<std::thread> processes;
    int num_processes = std::thread::hardware_concurrency();

    for (int i = 0; i < num_processes; ++i) {
        processes.emplace_back(find_solution, std::ref(unique_solutions), std::ref(solutions_lock), std::ref(target_addresses), std::ref(found_event));
    }

    for (auto& p : processes) {
        p.join();
    }

    std::cout << "All unique solutions found (hexadecimal) are processed." << std::endl;
    return 0;
}
