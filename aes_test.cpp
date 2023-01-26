// The MIT License
// Copyright 2023 funanz <granz.fisherman@gmail.com>
// https://opensource.org/licenses/MIT
#include <bytes_literals.hpp>
#include "aes.hpp"

using namespace cheap_aes;
using namespace bytes_literals;

void test_aes128()
{
    constexpr auto key = 0x000102030405060708090a0b0c0d0e0f_bytes;
    constexpr aes128 aes(key);
    constexpr auto text = 0x00112233445566778899aabbccddeeff_bytes;
    constexpr auto enc = aes.encrypt(text);
    static_assert(enc == 0x69c4e0d86a7b0430d8cdb78070b4c55a_bytes);
    constexpr auto dec = aes.decrypt(enc);
    static_assert(dec == text);
}

void test_aes192()
{
    constexpr auto key = 0x000102030405060708090a0b0c0d0e0f1011121314151617_bytes;
    constexpr aes192 aes(key);
    constexpr auto text = 0x00112233445566778899aabbccddeeff_bytes;
    constexpr auto enc = aes.encrypt(text);
    static_assert(enc == 0xdda97ca4864cdfe06eaf70a0ec0d7191_bytes);
    constexpr auto dec = aes.decrypt(enc);
    static_assert(dec == text);
}

void test_aes256()
{
    constexpr auto key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f_bytes;
    constexpr aes256 aes(key);
    constexpr auto text = 0x00112233445566778899aabbccddeeff_bytes;
    constexpr auto enc = aes.encrypt(text);
    static_assert(enc == 0x8ea2b7ca516745bfeafc49904b496089_bytes);
    constexpr auto dec = aes.decrypt(enc);
    static_assert(dec == text);
}

int main()
{
    test_aes128();
    test_aes192();
    test_aes256();
}
