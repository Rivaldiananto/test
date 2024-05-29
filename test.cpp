#include <iostream>
#include <bitset>
#include <vector>
#include <string>
#include <gmp.h>
#include <chrono>
#include <cstdlib>
#include <sstream>
#include <iomanip>

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

    gmp_printf("Total kombinasi yang mungkin: %Zd\\n", totalCombinations);

    // Start time measurement
    auto start = std::chrono::steady_clock::now();

    mpz_t i;
    mpz_init_set_ui(i, 0);
    unsigned long count = 0;
    while(mpz_cmp(i, totalCombinations) < 0) {  // Iterate through all combinations
        unsigned long long combination = mpz_get_ui(i);
        std::string result;
        for (int j = 0; j < numPatterns; ++j) {
            int index = combination % 64;
            result += allCombinations[index];
            combination /= 64;
        }
        std::string hexResult = binaryToHex(result);  // Konversi ke heksadesimal
        // Tampilkan atau proses hasil hex
        std::cout << hexResult << std::endl;
        mpz_add_ui(i, i, 1);
        count++;
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    double seconds = elapsed_seconds.count();
    double rate = count / seconds;

    std::cout << "Total waktu eksekusi: " << seconds << " detik\\n";
    std::cout << "Operasi per detik: " << rate << std::endl;

    mpz_clear(totalCombinations);
    mpz_clear(i);
    return 0;
}
