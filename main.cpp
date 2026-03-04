#include <iostream>
#include <string>
#include "kyznechik.h"

/*
**
    Currently, the cipher does not have full encryption capabilities
    due to the lack of PKCS7 padding and file handling.

    IMPORTANT!!! The cipher implementation has not 
    been tested for compliance with RFC 7801 - GOST 31.12-2015.
    The cipher's correctness and compliance with the standard must be verified.
    I will be checking this soon...
*/
int main() {
    Kyznechik kyz;

    std::string word;
    std::getline(std::cin, word);
    std::array<uint8_t, 16> block;

    for (int i = 0; i < 16; i++) {
        block[i] = (int)word[i];
    }

    std::cout << "original block: ";
    for (auto& x : block) {
        std::cout << x << " ";
    }
    std::cout << "\n";

    kyz.encrypt_block(block.data());
    
    std::cout << "encrypted block: ";
    for (auto& x : block) {
        std::cout << x << " ";
    }
    std::cout << "\n";
}