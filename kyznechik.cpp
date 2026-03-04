#include <kyznechik.h>
#include <iostream>

void Kyznechik::S_transformation(uint8_t* p_inf) {
    for (int i = 0 ; i < 16 ; i++) {
        *p_inf=Kyznechik::S[*p_inf];
    }
}

void Kyznechik::S_transformation_inv(uint8_t* p_inf) {
    for (int i = 0 ; i < 16 ; i++) {
        *p_inf=Kyznechik::IS[*p_inf];
    }
}

void Kyznechik::R_transformation(uint8_t* p_inf) {
    uint8_t x = 0;

    // I'll finish later
}

uint8_t Kyznechik::GF_mul(uint8_t coeff, uint8_t p_inf) {
    uint8_t res = 0;

    for (int i = 0 ; i <= 7 ; i++) {
        if (p_inf & 0x01)
            res ^= coeff;
        
        coeff = (coeff << 1) ^ (coeff & 0x80 ? 0xC3 : 0x00);
        p_inf >>= 1;
    }

    for (int i = 0 ; i < 16 ; i++) {

    }

    return res;
}