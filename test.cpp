#include <iostream>
#include <iomanip>
#include <cmath>

int main() {
    // Nilai minimum dan maksimum
    long double min_val = 2.2000000000000000;
    long double max_val = 2.5931547296039625;
    // Nilai yang akan ditambahkan
    long double add_val = 19.250411886234843;
    // Tentukan langkah untuk iterasi
    long double step = 0.0000000000000001;

    // Hitung jumlah langkah yang diperlukan
    long long num_steps = static_cast<long long>((max_val - min_val) / step);

    std::cout << std::fixed << std::setprecision(16);

    // Iterasi dari min_val ke max_val
    for (long long i = 0; i <= num_steps; ++i) {
        long double val = min_val + i * step;
        long double result = val + add_val;
        std::cout << "Nilai asli: " << val << " , Nilai setelah ditambah: " << result << std::endl;
    }

    return 0;
}
