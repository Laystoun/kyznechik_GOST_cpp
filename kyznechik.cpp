#include "kyznechik.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <emmintrin.h>

void Kyznechik::S_transformation(uint8_t *p_inf)
{
    for (int i = 0; i < 16; i++)
    {
        p_inf[i] = S[p_inf[i]];
    }
}

void Kyznechik::S_transformation_inv(uint8_t *p_inf)
{
    for (int i = 0; i < 16; i++)
    {
        p_inf[i] = IS[p_inf[i]];
    }
}

void Kyznechik::R_transformation(uint8_t *p_inf)
{
    uint8_t x = 0;

    for (int i = 0; i < 16; i++)
    {
        x ^= L_COEFFS[i][p_inf[i]];
    }

    for (int i = 15; i > 0; i--)
    {
        p_inf[i] = p_inf[i - 1];
    }
    p_inf[0] = x;
}

void Kyznechik::L_transformation(uint8_t *p_inf)
{
    for (int i = 0; i < 16; i++)
    {
        R_transformation(p_inf);
    }
}

void Kyznechik::expand_keys()
{
    std::copy(master_key, master_key + 16, ROUND_KEYS[0].begin());
    std::copy(master_key + 16, master_key + 32, ROUND_KEYS[1].begin());

    auto k1 = ROUND_KEYS[0];
    auto k2 = ROUND_KEYS[1];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            auto temp = k1;

            for (int k = 0; k < 16; k++)
            {
                k1[k] ^= ITER_CONSTANTS[i * 8 + j][k];
            }

            S_transformation(k1.data());
            L_transformation(k1.data());

            for (int k = 0; k < 16; k++)
            {
                k1[k] ^= k2[k];
            }

            k2 = temp;
        }
        ROUND_KEYS[2 * i + 2] = k1;
        ROUND_KEYS[2 * i + 3] = k2;
    }
}

void Kyznechik::encrypt_block(uint8_t *p_inf)
{
    __m128i b0 = _mm_loadu_si128((__m128i *)(p_inf + 0));
    __m128i b1 = _mm_loadu_si128((__m128i *)(p_inf + 16));
    __m128i b2 = _mm_loadu_si128((__m128i *)(p_inf + 32));
    __m128i b3 = _mm_loadu_si128((__m128i *)(p_inf + 48));

    for (int i = 0; i < 9; i++)
    {
        __m128i key = _mm_loadu_si128((__m128i *)ROUND_KEYS[i].data());

        b0 = _mm_xor_si128(key, b0);
        b1 = _mm_xor_si128(key, b1);
        b2 = _mm_xor_si128(key, b2);
        b3 = _mm_xor_si128(key, b3);

        alignas(16) uint8_t t0[16], t1[16], t2[16], t3[16];
        _mm_store_si128((__m128i *)t0, b0);
        _mm_store_si128((__m128i *)t1, b1);
        _mm_store_si128((__m128i *)t2, b2);
        _mm_store_si128((__m128i *)t3, b3);

        b0 = _mm_setzero_si128();
        b1 = _mm_setzero_si128();
        b2 = _mm_setzero_si128();
        b3 = _mm_setzero_si128();

        for (int x = 0; x < 16; x++)
        {
            b0 = _mm_xor_si128(b0, _mm_loadu_si128((__m128i *)LS_TABLE[x][t0[x]].data()));
            b1 = _mm_xor_si128(b1, _mm_loadu_si128((__m128i *)LS_TABLE[x][t1[x]].data()));
            b2 = _mm_xor_si128(b2, _mm_loadu_si128((__m128i *)LS_TABLE[x][t2[x]].data()));
            b3 = _mm_xor_si128(b3, _mm_loadu_si128((__m128i *)LS_TABLE[x][t3[x]].data()));
        }
    }

    __m128i last_key = _mm_loadu_si128((__m128i *)ROUND_KEYS[9].data());
    b0 = _mm_xor_si128(last_key, b0);
    _mm_storeu_si128((__m128i *)(p_inf + 0), b0);
    b1 = _mm_xor_si128(last_key, b1);
    _mm_storeu_si128((__m128i *)(p_inf + 16), b1);
    b2 = _mm_xor_si128(last_key, b2);
    _mm_storeu_si128((__m128i *)(p_inf + 32), b2);
    b3 = _mm_xor_si128(last_key, b3);
    _mm_storeu_si128((__m128i *)(p_inf + 48), b3);
}

void Kyznechik::init()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 32; i++)
    {
        master_key[i] = static_cast<uint8_t>(dis(gen));
    }
    for (int i = 0; i < 32; i++)
    {
        std::array<uint8_t, 16> temp_c{0};
        temp_c[15] = (uint8_t)(i + 1);
        L_transformation(temp_c.data());
        ITER_CONSTANTS[i] = temp_c;
    }
}

void Kyznechik::L_tranformation_inv(uint8_t *p_inf)
{
    for (int i = 0; i < 16; i++)
    {
        R_transformation_inv(p_inf);
    }
}

void Kyznechik::R_transformation_inv(uint8_t *p_inf)
{
    uint8_t x = p_inf[0];

    for (int i = 0; i < 15; i++)
    {
        p_inf[i] = p_inf[i + 1];
    }

    p_inf[15] = x;

    uint8_t sum = 0;
    for (int i = 0; i < 16; i++)
    {
        sum ^= L_COEFFS[i][p_inf[i]];
    }

    p_inf[15] = sum;
}

void Kyznechik::decrypt_block(uint8_t *p_inf)
{
    __m128i block = _mm_loadu_si128((__m128i*)p_inf);
    __m128i key = _mm_loadu_si128((__m128i*)ROUND_KEYS[9].data());
    block = _mm_xor_si128(block, key);
    _mm_storeu_si128((__m128i*)p_inf, block);

    for (int i = 8; i >= 0; i--)
    {
        L_tranformation_inv(p_inf);
        S_transformation_inv(p_inf);
        
        __m128i i_block = _mm_loadu_si128((__m128i*)p_inf);
        __m128i i_key = _mm_loadu_si128((__m128i*)ROUND_KEYS[i].data());
        i_block = _mm_xor_si128(i_block, i_key);
        _mm_storeu_si128((__m128i*)p_inf, i_block);
    }
}