#include <iostream>
#include <string>
#include <fstream>
#include <cassert>
#include <array>
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
        }
    }
}
