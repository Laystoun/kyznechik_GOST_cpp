#ifndef PKCS_H
#define PKCS_H

#include <vector>
#include <cstdint>

void pkcspad(std::vector<uint8_t>& block);
void pkcsunpad(std::vector<uint8_t>& block);

#endif
