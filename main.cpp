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

        double total_sec_time = 0;
        std::vector<uint8_t> buffer(256 * 1024 * 1024);

        std::chrono::duration<double> total_encrypted_time(0);

        double encrypted_bytes_handl(0);
        auto start_program = std::chrono::high_resolution_clock::now();
        while(in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
            size_t read_bytes = in.gcount();

            if (in.eof()) {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }
            
            auto start = std::chrono::high_resolution_clock::now();
            #pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 128) {
                kyz.encrypt_block(buffer.data() + i);
            }
            auto end  = std::chrono::high_resolution_clock::now();
            total_encrypted_time += (end - start);
            encrypted_bytes_handl += read_bytes;

            out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
        }
        std::cout << "End encrypted..." << std::endl;

        std::size_t file_name = path.find_last_of("\\/");
        std::ofstream out_decrypt_file { "C:\\Users\\docer\\Desktop\\Files_Folders\\" + path.substr(file_name + 1), std::ios::binary };
        out.clear();
        out.seekg(0, std::ios::beg);
        
        std::chrono::duration<double> total_decrypt_time { 0 };
        auto decryption_bytes_hand { 0 };
        while(out.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || out.gcount() > 0) {
            size_t check_bytes = out.gcount();

            auto start_decrypt = std::chrono::high_resolution_clock::now();
            #pragma omp parallel for
            for (int i = 0; i < check_bytes; i += 16) {
                kyz.decrypt_block(buffer.data() + i);
            }
            auto end_decrypt = std::chrono::high_resolution_clock::now();
            total_decrypt_time += (end_decrypt - start_decrypt);
            decryption_bytes_hand += check_bytes;

            if (out.peek() == EOF) {
                buffer.resize(check_bytes);
                pkcsunpad(buffer);
                check_bytes = buffer.size();
            }

            out_decrypt_file.write(reinterpret_cast<char*>(buffer.data()), check_bytes);
        }
        
        auto end_program = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> encrypted_time = total_encrypted_time / 60;
        std::chrono::duration<double> decrypted_time = total_decrypt_time / 60;

        std::chrono::duration<double> total_program_time = end_program - start_program;
        std::cout << 
            "Program time (s): " << total_program_time.count() << std::endl <<
            "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl <<
            "Encrypted TIME (s): " << encrypted_time.count() << std::endl <<
            "Decrypted MB/s: " << (decryption_bytes_hand / (1024 * 1024)) / total_decrypt_time.count() << std::endl <<
            "Decrypted TIME (s): " << decrypted_time.count() << std::endl;
    }
}
