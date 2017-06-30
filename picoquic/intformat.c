#include <stdint.h>

void picoformat_16(uint8_t *bytes, uint16_t n16)
{
    bytes[0] = (uint8_t)(n16 >> 8);
    bytes[1] = (uint8_t)(n16);
}

void picoformat_32(uint8_t *bytes, uint32_t n32)
{
    bytes[0] = (uint8_t)(n32 >> 24);
    bytes[1] = (uint8_t)(n32 >> 16);
    bytes[2] = (uint8_t)(n32 >> 8);
    bytes[3] = (uint8_t)(n32);
}

void picoformat_64(uint8_t *bytes, uint64_t n64)
{
    bytes[0] = (uint8_t)(n64 >> 56);
    bytes[1] = (uint8_t)(n64 >> 48);
    bytes[2] = (uint8_t)(n64 >> 40);
    bytes[3] = (uint8_t)(n64 >> 32);
    bytes[4] = (uint8_t)(n64 >> 24);
    bytes[5] = (uint8_t)(n64 >> 16);
    bytes[6] = (uint8_t)(n64 >> 8);
    bytes[7] = (uint8_t)(n64);
}