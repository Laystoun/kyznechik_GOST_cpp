#include "kyznechik.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <emmintrin.h>

void Kyznechik::S_transformation(uint8_t* p_inf) {
    for (int i = 0 ; i < 16 ; i++) {
        p_inf[i]=S[p_inf[i]];
    }
}

void Kyznechik::S_transformation_inv(uint8_t* p_inf) {
    for (int i = 0 ; i < 16 ; i++) {
        p_inf[i]=IS[p_inf[i]];
    }
}

void Kyznechik::R_transformation(uint8_t* p_inf) {
    uint8_t x = 0;

    for (int i = 0 ; i < 16 ; i++) {
        x ^= L_COEFFS[i][p_inf[i]];
    }

    for(int i = 15; i > 0; i--) {
        p_inf[i] = p_inf[i - 1];
    }
    p_inf[0] = x;
}

void Kyznechik::L_transformation(uint8_t* p_inf) {
    for (int i = 0; i < 16; i++) {
        R_transformation(p_inf);
    }
}

void Kyznechik::expand_keys() {
    std::copy(master_key, master_key + 16, ROUND_KEYS[0].begin());
    std::copy(master_key + 16, master_key + 32, ROUND_KEYS[1].begin());

    auto k1 = ROUND_KEYS[0];
    auto k2 = ROUND_KEYS[1];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            auto temp = k1;

            for (int k = 0; k < 16; k++) {
                k1[k] ^= ITER_CONSTANTS[i * 8 + j][k];
            }

            S_transformation(k1.data());
            L_transformation(k1.data());

            for(int k = 0; k < 16; k++) {
                k1[k] ^= k2[k];
            }

            k2 = temp;
        }
        ROUND_KEYS[2 * i + 2] = k1;
        ROUND_KEYS[2 * i + 3] = k2;
    }
}

void Kyznechik::encrypt_block(uint8_t* p_inf) {

    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 16; j++) {
            __m128i block = _mm_loadu_si128((__m128i*)p_inf);
            __m128i key = _mm_loadu_si128((__m128i*)ROUND_KEYS[i].data());
            block = _mm_xor_si128(block, key);
            _mm_storeu_si128((__m128i*)p_inf, block);
        }
        
        __m128i res = _mm_setzero_si128();
        for (int x = 0; x < 16; x++) {
            __m128i entry = _mm_loadu_si128((__m128i*)LS_TABLE[x][p_inf[x]].data());
            res = _mm_xor_si128(res, entry);
        }
        _mm_storeu_si128((__m128i*)p_inf, res);
    }

    __m128i block = _mm_loadu_si128((__m128i*)p_inf);
    __m128i key = _mm_loadu_si128((__m128i*)ROUND_KEYS[9].data());
    block = _mm_xor_si128(block, key);
    _mm_storeu_si128((__m128i*)p_inf, block);
}

void Kyznechik::init() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 32; i++) {
        master_key[i] = static_cast<uint8_t>(dis(gen));
    }
    for (int i = 0; i < 32; i++) {
        std::array<uint8_t, 16> temp_c {0};
        temp_c[15] = (uint8_t)(i + 1);
        L_transformation(temp_c.data());
        ITER_CONSTANTS[i] = temp_c;
    }
}

void Kyznechik::L_tranformation_inv(uint8_t* p_inf) {
    for(int i = 0; i < 16; i++) {
        R_transformation_inv(p_inf);
    }
}

void Kyznechik::R_transformation_inv(uint8_t* p_inf) {
    uint8_t x = p_inf[0];

    for (int i = 0; i < 15; i++) {
        p_inf[i] = p_inf[i + 1];
    }

    p_inf[15] = x;

    uint8_t sum = 0;
    for (int i = 0; i < 16; i++) {
        sum ^= L_COEFFS[i][p_inf[i]];
    }

    p_inf[15] = sum;
}

void Kyznechik::decrypt_block(uint8_t* p_inf) {
    for(int i = 0; i < 16; i++) {
        p_inf[i] ^= ROUND_KEYS[9][i];
    }

    for (int i = 8; i >= 0; i--) {
        L_tranformation_inv(p_inf);
        S_transformation_inv(p_inf);
        for (int j = 0; j < 16; j++) {
            p_inf[j] ^= ROUND_KEYS[i][j];
        }
    }
}