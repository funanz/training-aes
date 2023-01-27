// The MIT License
// Copyright 2023 funanz <granz.fisherman@gmail.com>
// https://opensource.org/licenses/MIT
#include <stdexcept>
#include <bytes_literals.hpp>
#include "aes_x86.hpp"

using namespace cheap_aes::x86;
using namespace bytes_literals;

#define runtime_assert(expr) { if (!(expr)) throw std::logic_error(#expr); }

void test_aes128_x86()
{
    auto key = 0x000102030405060708090a0b0c0d0e0f_bytes;
    aes128 aes(key);
    auto text = 0x00112233445566778899aabbccddeeff_bytes;
    auto enc = aes.encrypt(text);
    runtime_assert(enc == 0x69c4e0d86a7b0430d8cdb78070b4c55a_bytes);
    auto dec = aes.decrypt(enc);
    runtime_assert(dec == text);
}

void test_aes192_x86()
{
    auto key = 0x000102030405060708090a0b0c0d0e0f1011121314151617_bytes;
    aes192 aes(key);
    auto text = 0x00112233445566778899aabbccddeeff_bytes;
    auto enc = aes.encrypt(text);
    runtime_assert(enc == 0xdda97ca4864cdfe06eaf70a0ec0d7191_bytes);
    auto dec = aes.decrypt(enc);
    runtime_assert(dec == text);
}

void test_aes256_x86()
{
    auto key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f_bytes;
    aes256 aes(key);
    auto text = 0x00112233445566778899aabbccddeeff_bytes;
    auto enc = aes.encrypt(text);
    runtime_assert(enc == 0x8ea2b7ca516745bfeafc49904b496089_bytes);
    auto dec = aes.decrypt(enc);
    runtime_assert(dec == text);
}

int main()
{
    test_aes128_x86();
    test_aes192_x86();
    test_aes256_x86();
}
