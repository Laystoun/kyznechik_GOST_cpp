#include "pkcs.h"
#include <iostream>
#include <cassert>

void pkcspad(std::vector<uint8_t>& block) {
    uint8_t pad_len = 16 - (block.size() % 16);

    for (int i = 0; i < pad_len; i++) {
        block.push_back(pad_len);
    }
}

void pkcsunpad(std::vector<uint8_t>& block) {
    uint8_t pad_val = block.back();
    if (pad_val == 0 || pad_val > 16 || pad_val > block.size()) {
        std::cerr << "Error: Invalid padding value (" << (int)pad_val << "). Wrong key?" << std::endl;
        return; 
    }
    block.resize(block.size() - pad_val);
}