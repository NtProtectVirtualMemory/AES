#pragma once
#include <cstdint>
#include "tables.h"

namespace AES 
{
	static inline uint8_t gf_mul2(uint8_t a)
	{
		return (a << 1) ^ ((a >> 7) ? 0x1b : 0x00);
	}

	inline uint8_t gf_mul(uint8_t a, uint8_t b)
	{
		uint8_t result = 0;
		while (b)
		{
			if (b & 1) result ^= a;
			a = gf_mul2(a);
			b >>= 1;
		}
		return result;
	}

	static inline void rot_word(uint8_t w[4])
	{
		uint8_t tmp = w[0];
		w[0] = w[1];
		w[1] = w[2];
		w[2] = w[3];
		w[3] = tmp;
	}

	static inline void sub_word(uint8_t w[4])
	{
		w[0] = sbox(w[0]);
		w[1] = sbox(w[1]);
		w[2] = sbox(w[2]);
		w[3] = sbox(w[3]);
	}
	
} // namespace aes