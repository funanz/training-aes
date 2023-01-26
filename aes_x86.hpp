#pragma once
// The MIT License
// Copyright 2023 funanz <granz.fisherman@gmail.com>
// https://opensource.org/licenses/MIT
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace cheap_aes::x86
{
    template <int Nk, int Nb, int Nr>
    class aes_base
    {
    public:
        static constexpr int key_size() { return 4 * Nk; };
        static constexpr int block_size() { return 4 * Nb; };
        using key_array = std::array<std::uint8_t, key_size()>;
        using block_array = std::array<std::uint8_t, block_size()>;

    private:
        __m128i w[Nr+1];
        __m128i dw[Nr+1];

    public:
        aes_base() {}

        explicit aes_base(const std::uint8_t key[4*Nk]) {
            key_expansion(&key[0], &w[0], &dw[0]);
        }

        explicit aes_base(const key_array& key) {
            key_expansion(&key[0], &w[0], &dw[0]);
        }

        void set(const std::uint8_t key[4*Nk]) {
            key_expansion(&key[0], &w[0], &dw[0]);
        }

        void set(const key_array& key) {
            key_expansion(&key[0], &w[0], &dw[0]);
        }

        void encrypt(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb]) const {
            cipher(&in[0], &out[0], &w[0]);
        }

        void encrypt(const block_array& in, block_array& out) const {
            cipher(&in[0], &out[0], &w[0]);
        }

        block_array encrypt(const block_array& in) const {
            block_array out;
            cipher(&in[0], &out[0], &w[0]);
            return out;
        }

        void decrypt(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb]) const {
            inv_cipher(&in[0], &out[0], &dw[0]);
        }

        void decrypt(const block_array& in, block_array& out) const {
            inv_cipher(&in[0], &out[0], &dw[0]);
        }

        block_array decrypt(const block_array& in) const {
            block_array out;
            inv_cipher(&in[0], &out[0], &dw[0]);
            return out;
        }

    private:
        static void key_expansion(const std::uint8_t key[4*Nk], __m128i w[Nr+1], __m128i dw[Nr+1]) {
            if constexpr (Nk == 4 && Nb == 4 && Nr == 10)
                key_expansion_128(key, w);
            else if constexpr (Nk == 6 && Nb == 4 && Nr == 12)
                key_expansion_192(key, w);
            else if constexpr (Nk == 8 && Nb == 4 && Nr == 14)
                key_expansion_256(key, w);
            else
                key_expansion_gen(key, w);

            inv_key(w, dw);
        }

        static void key_expansion_gen(const std::uint8_t key[4*Nk], __m128i w[Nr+1]) {
            std::memcpy(w, key, 4*Nk);

            auto pw = (std::uint32_t*)w;
            for (int i = Nk; i < Nb*(Nr+1); i++) {
                auto temp = pw[i-1];
                if (i % Nk == 0)
                    temp = sub_word(rot_word(temp)) ^ rcon[i/Nk];
                else if (Nk > 6 && i % Nk == 4)
                    temp = sub_word(temp);
                pw[i] = pw[i-Nk] ^ temp;
            }
        }

        static constexpr std::uint32_t word(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
            return a | b << 8 | c << 16 | d << 24;
        }

        static constexpr std::uint32_t sub_word(std::uint32_t n) {
            return word(sbox[n & 0xff],
                        sbox[n >> 8 & 0xff],
                        sbox[n >> 16 & 0xff],
                        sbox[n >> 24 & 0xff]);
        }

        static constexpr std::uint32_t rot_word(std::uint32_t n) {
            return std::rotr(n, 8);
        }

        static void key_expansion_128(const std::uint8_t key[16], __m128i w[11]) {
            std::memcpy(w, key, 16);

            auto sw = _mm_aeskeygenassist_si128(w[0], 0x01);
            key_expansion_128_update(w, 0, 1, sw);
            sw = _mm_aeskeygenassist_si128(w[1], 0x02);
            key_expansion_128_update(w, 1, 2, sw);
            sw = _mm_aeskeygenassist_si128(w[2], 0x04);
            key_expansion_128_update(w, 2, 3, sw);
            sw = _mm_aeskeygenassist_si128(w[3], 0x08);
            key_expansion_128_update(w, 3, 4, sw);
            sw = _mm_aeskeygenassist_si128(w[4], 0x10);
            key_expansion_128_update(w, 4, 5, sw);
            sw = _mm_aeskeygenassist_si128(w[5], 0x20);
            key_expansion_128_update(w, 5, 6, sw);
            sw = _mm_aeskeygenassist_si128(w[6], 0x40);
            key_expansion_128_update(w, 6, 7, sw);
            sw = _mm_aeskeygenassist_si128(w[7], 0x80);
            key_expansion_128_update(w, 7, 8, sw);
            sw = _mm_aeskeygenassist_si128(w[8], 0x1b);
            key_expansion_128_update(w, 8, 9, sw);
            sw = _mm_aeskeygenassist_si128(w[9], 0x36);
            key_expansion_128_update(w, 9, 10, sw);
        }

        static inline void key_expansion_128_update(__m128i w[11], int in, int out, __m128i sw) {
            auto x = w[in];
            x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
            x = _mm_xor_si128(x, _mm_slli_si128(x, 8));
            x = _mm_xor_si128(x, _mm_shuffle_epi32(sw, 0xff));
            w[out] = x;
        }

        static void key_expansion_192(const std::uint8_t key[24], __m128i w[13]) {
            std::memcpy(w, key, 24);

            __m128i state[2] = { w[0], w[1] };
            auto sw = _mm_aeskeygenassist_si128(state[1], 0x01);
            key_expansion_192_update(state, w, 1, 2, sw);
            sw = _mm_aeskeygenassist_si128(state[1], 0x02);
            key_expansion_192_update(state, w, 3, 4, sw, false);
            sw = _mm_aeskeygenassist_si128(state[1], 0x04);
            key_expansion_192_update(state, w, 4, 5, sw);
            sw = _mm_aeskeygenassist_si128(state[1], 0x08);
            key_expansion_192_update(state, w, 6, 7, sw, false);
            sw = _mm_aeskeygenassist_si128(state[1], 0x10);
            key_expansion_192_update(state, w, 7, 8, sw);
            sw = _mm_aeskeygenassist_si128(state[1], 0x20);
            key_expansion_192_update(state, w, 9, 10, sw, false);
            sw = _mm_aeskeygenassist_si128(state[1], 0x40);
            key_expansion_192_update(state, w, 10, 11, sw);
            sw = _mm_aeskeygenassist_si128(state[1], 0x80);
            key_expansion_192_update(state, w, 12, -1, sw, false);
        }

        static inline void key_expansion_192_update(
            __m128i s[2], __m128i w[13], int out_lo, int out_hi,
            __m128i sw, bool shift = true) {
            s[0] = _mm_xor_si128(s[0], _mm_slli_si128(s[0], 4));
            s[0] = _mm_xor_si128(s[0], _mm_slli_si128(s[0], 8));
            s[0] = _mm_xor_si128(s[0], _mm_shuffle_epi32(sw, 0x55));
            s[1] = _mm_xor_si128(s[1], _mm_slli_si128(s[1], 4));
            s[1] = _mm_xor_si128(s[1], _mm_shuffle_epi32(s[0], 0xff));

            if (shift) {
                w[out_lo] = _mm_unpacklo_epi64(w[out_lo], s[0]);
                if (out_hi >= 0)
                    w[out_hi] = _mm_alignr_epi8(s[1], s[0], 8);
            } else {
                w[out_lo] = s[0];
                if (out_hi >= 0)
                    w[out_hi] = s[1];
            }
        }

        static void key_expansion_256(const std::uint8_t key[32], __m128i w[15]) {
            std::memcpy(w, key, 32);

            auto sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[1], 0x01), 0xff);
            key_expansion_256_update(w, 0, 2, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[2], 0x01), 0xaa);
            key_expansion_256_update(w, 1, 3, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[3], 0x02), 0xff);
            key_expansion_256_update(w, 2, 4, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[4], 0x02), 0xaa);
            key_expansion_256_update(w, 3, 5, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[5], 0x04), 0xff);
            key_expansion_256_update(w, 4, 6, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[6], 0x04), 0xaa);
            key_expansion_256_update(w, 5, 7, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[7], 0x08), 0xff);
            key_expansion_256_update(w, 6, 8, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[8], 0x08), 0xaa);
            key_expansion_256_update(w, 7, 9, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[9], 0x10), 0xff);
            key_expansion_256_update(w, 8, 10, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[10], 0x10), 0xaa);
            key_expansion_256_update(w, 9, 11, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[11], 0x20), 0xff);
            key_expansion_256_update(w, 10, 12, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[12], 0x20), 0xaa);
            key_expansion_256_update(w, 11, 13, sw);
            sw = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(w[13], 0x40), 0xff);
            key_expansion_256_update(w, 12, 14, sw);
        }

        static inline void key_expansion_256_update(__m128i w[15], int in, int out, __m128i sw) {
            auto x = w[in];
            x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
            x = _mm_xor_si128(x, _mm_slli_si128(x, 8));
            x = _mm_xor_si128(x, sw);
            w[out] = x;
        }

        static void inv_key(const __m128i w[Nr+1], __m128i dw[Nr+1]) {
            dw[Nr] = w[0];
            for (int i = 1; i < Nr; i++)
                dw[Nr-i] = _mm_aesimc_si128(w[i]);
            dw[0] = w[Nr];
        }

        static void cipher(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb], const __m128i w[Nr+1]) {
            auto state = _mm_loadu_si128((__m128i*)in);

            state = _mm_xor_si128(state, w[0]);
            for (int i = 1; i < Nr; i++)
                state = _mm_aesenc_si128(state, w[i]);
            state = _mm_aesenclast_si128(state, w[Nr]);

            _mm_storeu_si128((__m128i*)out, state);
        }

        static void inv_cipher(const std::uint8_t in[4*Nb], std::uint8_t out[4*Nb], const __m128i dw[Nr+1]) {
            auto state = _mm_loadu_si128((__m128i*)in);

            state = _mm_xor_si128(state, dw[0]);
            for (int i = 1; i < Nr; i++)
                state = _mm_aesdec_si128(state, dw[i]);
            state = _mm_aesdeclast_si128(state, dw[Nr]);

            _mm_storeu_si128((__m128i*)out, state);
        }

        static constexpr std::uint8_t rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
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

        static_assert(sizeof(__m128i) == block_size());
    };

    using aes128 = aes_base<4, 4, 10>;
    using aes192 = aes_base<6, 4, 12>;
    using aes256 = aes_base<8, 4, 14>;
}
