#include <iostream>
#include <string>
#include <fstream>
#include <cassert>
#include <array>
#include <chrono>
#include "pkcs.h"
#include "kyznechik.h"

int main() {
    Kyznechik kyz; kyz.init();
    
    std::cout << "enter PATH #: ";
    std::string path;
    std::getline(std::cin, path);
    {
        std::ifstream in { path, std::ios::binary };
        std::ofstream out { path + ".enc", std::ios::binary };
        assert(in && "In file not found");

        auto start = std::chrono::high_resolution_clock::now();
        size_t total_processed_bytes = 0;
        std::vector<uint8_t> buffer(1024*1024);
        while(in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
            size_t read_bytes = in.gcount();

            if (in.eof()) {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }

            for (size_t i = 0; i < read_bytes; i += 16) {
                kyz.encrypt_block(buffer.data() + i);
            }
            out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
            total_processed_bytes += read_bytes;
        }

            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> time = end - start;
            double seconds = time.count();

            double mb = static_cast<double>(total_processed_bytes) / (1024 * 1024);
            std::cout << "MB/s: " << (double)mb/seconds << std::endl;
    }
}
