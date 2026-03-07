#include <iostream>
#include <string>
#include <fstream>
#include <cassert>
#include <array>
#include <chrono>
#include "pkcs.h"
#include "kyznechik.h"
#include <omp.h>

int main() {
    Kyznechik kyz; kyz.init();

    std::cout << "enter PATH #: ";
    std::string path;
    std::getline(std::cin, path);
    {
        std::ifstream in { path, std::ios::binary };
        std::fstream out { path + ".enc", std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc };
        assert(in && "In file not found");

        auto start = std::chrono::high_resolution_clock::now();
        size_t bytes_count = 0;
        double total_sec_time = 0;
        std::vector<uint8_t> buffer(256 * 1024 * 1024);
        while(in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
            size_t read_bytes = in.gcount();

            if (in.eof()) {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }

            auto t1 = std::chrono::high_resolution_clock::now();
            
            #pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 64) {
                kyz.encrypt_block(buffer.data() + i);
            }
            auto t2 = std::chrono::high_resolution_clock::now();
            bytes_count += read_bytes;
            total_sec_time += std::chrono::duration<double>(t2 - t1).count();

            out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
        }

        double mb = static_cast<double>(bytes_count) / (1024.0 * 1024.0);
        double speed = mb / total_sec_time;

        std::cout << "Processed MB: " << mb << std::endl;
        std::cout << "Total Crypto Time: " << total_sec_time << " s" << std::endl;
        std::cout << "Speed: " << speed << " MB/s" << std::endl;
    }

    std::string s;
    std::cin >> s;
}
