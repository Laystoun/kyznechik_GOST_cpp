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
    Kyznechik kyz; kyz.init();

    std::string word;
    std::getline(std::cin, word);
    std::array<uint8_t, 16> block;

    for (int i = 0; i < 16; i++) {
        block[i] = word[i];
    }

    kyz.encrypt_block(block.data());
    std::cout << "Encrypted block: ";
    for(auto& x : block) {
        std::cout << x;
    }
    std::cout << std::endl;

    kyz.decrypt_block(block.data());
    std::cout << "Decrypted block: ";
    for(auto& x : block) {
        std::cout << x;
    }
    std::cout << std::endl;
}

/*

Testing functions according to GOST

Official document assigned to the code: https://datatracker.ietf.org/doc/html/rfc7801

<===== S-Blocks ====>

RFC 7801:

5.1.  Transformation S
   S(ffeeddccbbaa99881122334455667700) = b66cd8887d38e8d77765aeea0c9a7efc,
   S(b66cd8887d38e8d77765aeea0c9a7efc) = 559d8dd7bd06cbfe7e7b262523280d39,
   S(559d8dd7bd06cbfe7e7b262523280d39) = 0c3322fed531e4630d80ef5c5a81c50b,
   S(0c3322fed531e4630d80ef5c5a81c50b) = 23ae65633f842d29c5df529c13f5acda.

Realization input-output:
    b66cd8887d38e8d77765aeeac9a7efc
    559d8dd7bd6cbfe7e7b26252328d39
    c3322fed531e463d80ef5c5a81c5b
    23ae65633f842d29c5df529c13f5acda

Testing code:
    Kyznechik kyz;

    std::array<uint8_t, 16> block {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
        0x99, 0x88, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x00
    };

    for (int i = 0 ; i < 4; i++) {
        kyz.S_transformation(block.data());
        for(auto& x : block) {
            std::cout << std::hex << (int)x;
        }
        std::cout << std::endl;
    }

<===== R-transformation =====>

RFC 7801:
    5.2.  Transformation R
        R(00000000000000000000000000000100) = 94000000000000000000000000000001,
        R(94000000000000000000000000000001) = a5940000000000000000000000000000,
        R(a5940000000000000000000000000000) = 64a59400000000000000000000000000,
        R(64a59400000000000000000000000000) = 0d64a594000000000000000000000000.

My input-output result:
    94000000000000001
    a59400000000000000
    64a5940000000000000
    d64a594000000000000

Testing code:
    Kyznechik kyz;

    std::array<uint8_t, 16> block = {
        0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0x01, 0x00
    };

    for (int i = 0 ; i < 4; i++) {
        kyz.R_transformation(block.data());
        for(auto& x : block) {
            std::cout << std::hex << (int)x;
        }
        std::cout << std::endl;
    }

<===== L_Transformation =====>

RFC 7801:
5.3.  Transformation L
   L(64a59400000000000000000000000000) = d456584dd0e3e84cc3166e4b7fa2890d,
   L(d456584dd0e3e84cc3166e4b7fa2890d) = 79d26221b87b584cd42fbc4ffea5de9a,
   L(79d26221b87b584cd42fbc4ffea5de9a) = 0e93691a0cfc60408b7b68f66b513c13,
   L(0e93691a0cfc60408b7b68f66b513c13) = e6a8094fee0aa204fd97bcb0b44b8580.

My Input-output:
    d456584dd0e3e84cc3166e4b7fa289d
    79d26221b87b584cd42fbc4ffea5de9a
    e93691acfc60408b7b68f66b513c13
    e6a894feeaa24fd97bcb0b44b8580

Code testing:
    Kyznechik kyz;

    std::array<uint8_t, 16> block = {
        0x64, 0xa5, 0x94, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0
    };

    for (int i = 0 ; i < 4; i++) {
        kyz.L_transformation(block.data());
        for(auto& x : block) {
            std::cout << std::hex << (int)x;
        }
        std::cout << std::endl;
    }

<===== expand key (key shedule) =====>
RFC 7801:

5.4 Key Schedule:
    C_1 = 6ea276726c487ab85d27bd10dd849401,
    C_2 = dc87ece4d890f4b3ba4eb92079cbeb02, F [C_2]F [C_1](K_1, K_2) = (37777748e56453377d5e262d90903f87, c3d5fa01ebe36f7a9374427ad7ca8949).
    C_3 = b2259a96b4d88e0be7690430a44f7f03,F[C_3]...F[C_1](K_1, K_2) = (f9eae5f29b2815e31f11ac5d9c29fb01, 37777748e56453377d5e262d90903f87).
    C_4 = 7bcd1b0b73e32ba5b79cb140f2551504,F[C_4]...F[C_1](K_1, K_2) = (e980089683d00d4be37dd3434699b98f, f9eae5f29b2815e31f11ac5d9c29fb01).
    C_5 = 156f6d791fab511deabb0c502fd18105, F[C_5]...F[C_1](K_1, K_2) = (b7bd70acea4460714f4ebe13835cf004, e980089683d00d4be37dd3434699b98f).
    C_6 = a74af7efab73df160dd208608b9efe06, F[C_6]...F[C_1](K_1, K_2) = (1a46ea1cf6ccd236467287df93fdf974, b7bd70acea4460714f4ebe13835cf004).
    C_7 = c9e8819dc73ba5ae50f5b570561a6a07, F[C_7]...F [C_1](K_1, K_2) = (3d4553d8e9cfec6815ebadc40a9ffd04, 1a46ea1cf6ccd236467287df93fdf974). 
    C_8 = f6593616e6055689adfba18027aa2a08, (K_3, K_4) = F [C_8]...F [C_1](K_1, K_2) = (db31485315694343228d6aef8cc78c44, 3d4553d8e9cfec6815ebadc40a9ffd04).
    
    K_1 = 8899aabbccddeeff0011223344556677,
    K_2 = fedcba98765432100123456789abcdef,
    K_3 = db31485315694343228d6aef8cc78c44,
    K_4 = 3d4553d8e9cfec6815ebadc40a9ffd04,
    K_5 = 57646468c44a5e28d3e59246f429f1ac,
    K_6 = bd079435165c6432b532e82834da581b,
    K_7 = 51e640757e8745de705727265a0098b1,
    K_8 = 5a7925017b9fdd3ed72a91a22286f984,
    K_9 = bb44e25378c73123a5f32f73cdb6e517,
    K_10 = 72e9dd7416bcf45b755dbaa88e4a4043.

My input-output:
        CI_1: 6ea276726c487ab85d27bd10dd84941
        CI_2: dc87ece4d890f4b3ba4eb92079cbeb2
        CI_3: b2259a96b4d88ebe769430a44f7f3
        CI_4: 7bcd1bb73e32ba5b79cb140f255154
        CI_5: 156f6d791fab511deabbc502fd1815
        CI_6: a74af7efab73df16dd28608b9efe6
        CI_7: c9e8819dc73ba5ae50f5b570561a6a7
        CI_8: f6593616e655689adfba18027aa2a8
    rounded keys:
        8899aabbccddeeff011223344556677
        fedcba9876543210123456789abcdef
        db31485315694343228d6aef8cc78c44
        3d4553d8e9cfec6815ebadc4a9ffd4
        57646468c44a5e28d3e59246f429f1ac
        bd79435165c6432b532e82834da581b
        51e640757e8745de705727265a098b1
        5a792517b9fdd3ed72a91a22286f984
        bb44e25378c73123a5f32f73cdb6e517
        72e9dd7416bcf45b755dbaa88e4a4043

Code for test:
    insert to Kyznechik.h:
    
    uint8_t master_key[32] {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef
    };

    insert to function expand_keys in down:
    
    std::cout << "rounded keys:" << std::endl;
    for(auto& x : ROUND_KEYS) {
        for (auto& xx : x) {
            std::cout << std::hex << (int)xx; 
        }
        std::cout << "\n";
    }

    insert to function init() after initializied ITER_CONSTANTS:
    if (i < 8) {
            std::cout << "CI_" << i + 1 << ": ";
            for (int x = 0 ; x < 16; x++) {
                std::cout << std::hex << (int)ITER_CONSTANTS[i][x];
            }
            std::cout << std::endl;
        }
*/