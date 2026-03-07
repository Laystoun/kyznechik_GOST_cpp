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
        std::fstream out { path + ".enc", std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc };
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

            for (size_t i = 0; i < read_bytes; i += 64) {
                kyz.encrypt_block(buffer.data() + i);
            }
            out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
            total_processed_bytes += read_bytes;
        }

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> time = end - start;
        double seconds = time.count();

        double mb = static_cast<double>(total_processed_bytes) / (1024 * 1024);
        std::cout << "encrypted MB/s: " << (double)mb/seconds << std::endl;

        std::ofstream out_decrypt_file{ path + ".dec" , std::ios::binary };
        
        out.clear();
        out.seekg(0, std::ios::beg);
        while(out.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || out.gcount() > 0) {
            std::cout << "decrypt" << std::endl;
            size_t check_bytes = out.gcount();

            for (int i = 0; i < check_bytes; i += 16) {
                kyz.decrypt_block(buffer.data() + i);
            }
            
            if (out.peek() == EOF) {
                buffer.resize(check_bytes);
                pkcsunpad(buffer);
                check_bytes = buffer.size();
            }

            out_decrypt_file.write(reinterpret_cast<char*>(buffer.data()), check_bytes);
        }
    }
}
