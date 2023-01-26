#pragma once
// The MIT License
// Copyright 2023 funanz <granz.fisherman@gmail.com>
// https://opensource.org/licenses/MIT
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>

namespace cheap_aes
{
    template <int Nk, int Nb, int Nr>
    class aes_base
    {
    public:
        static constexpr int key_size() { return 4 * Nk; };
        static constexpr int block_size() { return 4 * Nb; };
        static constexpr int work_size() { return Nb * (Nr + 1); };
        using key_array = std::array<std::uint8_t, key_size()>;
        using block_array = std::array<std::uint8_t, block_size()>;
        using work_array = std::array<std::uint32_t, work_size()>;

    private:
        work_array w;

    public:
        constexpr aes_base() {}

        constexpr explicit aes_base(const std::uint8_t key[4*Nk]) {
            key_expansion(&key[0], &w[0]);
        }

        constexpr explicit aes_base(const key_array& key) {
            key_expansion(&key[0], &w[0]);
        }

        constexpr void set(const std::uint8_t key[4*Nk]) {
            key_expansion(&key[0], &w[0]);
        }

        constexpr void set(const key_array& key) {
            key_expansion(&key[0], &w[0]);
        }

        constexpr void encrypt(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb]) const {
            cipher(&in[0], &out[0], &w[0]);
        }

        constexpr void encrypt(const block_array& in, block_array& out) const {
            cipher(&in[0], &out[0], &w[0]);
        }

        constexpr block_array encrypt(const block_array& in) const {
            block_array out;
            cipher(&in[0], &out[0], &w[0]);
            return out;
        }

        constexpr void decrypt(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb]) const {
            inv_cipher(&in[0], &out[0], &w[0]);
        }

        constexpr void decrypt(const block_array& in, block_array& out) const {
            inv_cipher(&in[0], &out[0], &w[0]);
        }

        constexpr block_array decrypt(const block_array& in) const {
            block_array out;
            inv_cipher(&in[0], &out[0], &w[0]);
            return out;
        }

    private:
        static constexpr void key_expansion(const std::uint8_t key[4*Nk], std::uint32_t w[Nb*(Nr+1)]) {
            for (int i = 0; i < Nk; i++)
                w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);

            for (int i = Nk; i < Nb*(Nr+1); i++) {
                auto temp = w[i-1];
                if (i % Nk == 0)
                    temp = sub_word(rot_word(temp)) ^ rcon[i/Nk];
                else if (Nk > 6 && i % Nk == 4)
                    temp = sub_word(temp);
                w[i] = w[i-Nk] ^ temp;
            }
        }

        static constexpr std::uint32_t word(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
            return a << 24 | b << 16 | c << 8 | d;
        }

        static constexpr std::uint32_t sub_word(std::uint32_t n) {
            return word(sbox[n >> 24 & 0xff],
                        sbox[n >> 16 & 0xff],
                        sbox[n >> 8 & 0xff],
                        sbox[n & 0xff]);
        }

        static constexpr std::uint32_t rot_word(std::uint32_t n) {
            return std::rotl(n, 8);
        }

        static constexpr void cipher(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb], const std::uint32_t w[Nb*(Nr+1)]) {
            std::uint8_t state[4*Nb];
            std::ranges::copy(in, in+4*Nb, state);

            add_round_key(state, &w[0]);

            for (int round = 1; round < Nr; round++) {
                sub_bytes(state);
                shift_rows(state);
                mix_colmns(state);
                add_round_key(state, &w[round*Nb]);
            }

            sub_bytes(state);
            shift_rows(state);
            add_round_key(state, &w[Nr*Nb]);

            std::ranges::copy(state, out);
        }

        static constexpr void add_round_key(std::uint8_t state[4*Nb], const std::uint32_t w[Nb]) {
            for (int i = 0; i < Nb; i++) {
                state[4*i+0] ^= w[i] >> 24;
                state[4*i+1] ^= w[i] >> 16;
                state[4*i+2] ^= w[i] >> 8;
                state[4*i+3] ^= w[i];
            }
        }

        static constexpr void sub_bytes(std::uint8_t state[4*Nb]) {
            for (int i = 0; i < 4*Nb; i++)
                state[i] = sbox[state[i]];
        }

        static constexpr void shift_rows(std::uint8_t state[4*Nb]) {
            auto s = &state[0];
            std::uint8_t sd[4*Nb] = {
                s[ 0], s[ 5], s[10], s[15],
                s[ 4], s[ 9], s[14], s[ 3],
                s[ 8], s[13], s[ 2], s[ 7],
                s[12], s[ 1], s[ 6], s[11],
            };
            std::ranges::copy(sd, state);
        }

        static constexpr void mix_colmns(std::uint8_t state[4*Nb]) {
            for (int i = 0; i < Nb; i++) {
                auto s = &state[4*i];
                std::uint8_t sd[4];
                sd[0] = gf256m(2, s[0]) ^ gf256m(3, s[1]) ^ s[2] ^ s[3];
                sd[1] = s[0] ^ gf256m(2, s[1]) ^ gf256m(3, s[2]) ^ s[3];
                sd[2] = s[0] ^ s[1] ^ gf256m(2, s[2]) ^ gf256m(3, s[3]);
                sd[3] = gf256m(3, s[0]) ^ s[1] ^ s[2] ^ gf256m(2, s[3]);
                std::ranges::copy(sd, s);
            }
        }

        static constexpr std::uint8_t gf256m(std::uint8_t a, std::uint8_t b) {
            std::uint8_t r = 0;
            for (int i = 0; i < 8; i++) {
                if (b & 1)
                    r ^= a;
                b >>= 1;
                a = xtime(a);
            }
            return r;
        }

        static constexpr std::uint8_t xtime(std::uint8_t n) {
            const auto n2 = n << 1;
            return (n & 0x80) ? (n2 ^ 0x1b) : n2;
        }

        static constexpr void inv_cipher(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb], const std::uint32_t w[Nb*(Nr+1)]) {
            std::uint8_t state[4*Nb];
            std::copy(in, in+4*Nb, state);

            add_round_key(state, &w[Nr*Nb]);

            for (int round = Nr-1; round > 0; round--) {
                inv_shift_rows(state);
                inv_sub_bytes(state);
                add_round_key(state, &w[round*Nb]);
                inv_mix_colmns(state);
            }

            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, &w[0]);

            std::ranges::copy(state, out);
        }

        static constexpr void inv_sub_bytes(std::uint8_t state[4*Nb]) {
            for (int i = 0; i < 4*Nb; i++)
                state[i] = inv_sbox[state[i]];
        }

        static constexpr void inv_shift_rows(std::uint8_t state[4*Nb]) {
            auto s = &state[0];
            std::uint8_t sd[4*Nb] = {
                s[ 0], s[13], s[10], s[ 7],
                s[ 4], s[ 1], s[14], s[11],
                s[ 8], s[ 5], s[ 2], s[15],
                s[12], s[ 9], s[ 6], s[ 3],
            };
            std::ranges::copy(sd, state);
        }

        static constexpr void inv_mix_colmns(std::uint8_t state[4*Nb]) {
            for (int i = 0; i < Nb; i++) {
                auto s = &state[4*i];
                std::uint8_t sd[4];
                sd[0] = gf256m(0x0e, s[0]) ^ gf256m(0x0b, s[1]) ^ gf256m(0x0d, s[2]) ^ gf256m(0x09, s[3]);
                sd[1] = gf256m(0x09, s[0]) ^ gf256m(0x0e, s[1]) ^ gf256m(0x0b, s[2]) ^ gf256m(0x0d, s[3]);
                sd[2] = gf256m(0x0d, s[0]) ^ gf256m(0x09, s[1]) ^ gf256m(0x0e, s[2]) ^ gf256m(0x0b, s[3]);
                sd[3] = gf256m(0x0b, s[0]) ^ gf256m(0x0d, s[1]) ^ gf256m(0x09, s[2]) ^ gf256m(0x0e, s[3]);
                std::ranges::copy(sd, s);
            }
        }

        static constexpr std::uint32_t rcon[11] = {
            0x00000000,
            0x01000000,
            0x02000000,
            0x04000000,
            0x08000000,
            0x10000000,
            0x20000000,
            0x40000000,
            0x80000000,
            0x1b000000,
            0x36000000,
        };

        static constexpr std::uint8_t sbox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        };

        static constexpr std::uint8_t inv_sbox[256] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
        };
    };

    using aes128 = aes_base<4, 4, 10>;
    using aes192 = aes_base<6, 4, 12>;
    using aes256 = aes_base<8, 4, 14>;
}
