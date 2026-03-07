#include "AES.h"
#include "tables.h"
#include "utils.h"
#include <cstdint>

namespace aes 
{
	void add_key(uint8_t in[16], const uint8_t key[16])
	{
		for (int i{ 0 }; i < 16; ++i)
		{
			in[i] ^= key[i];
		}
	}

	void sub_bytes(uint8_t in[16])
	{
		for (int i{ 0 }; i < 16; ++i)
		{
			in[i] = sbox(in[i]);
		}
	}

	void shift_rows(uint8_t s[16]) 
	{
		uint8_t temp{ 0 };

		// Row 1: rotate left by 1
		temp = s[4];
		s[4] = s[5];
		s[5] = s[6];
		s[6] = s[7];
		s[7] = temp;

		// Row 2: rotate left by 2
		temp = s[8];  s[8] = s[10];  s[10] = temp;
		temp = s[9];  s[9] = s[11];  s[11] = temp;

		// Row 3: rotate left by 3
		temp  = s[15];
		s[15] = s[14];
		s[14] = s[13];
		s[13] = s[12];
		s[12] = temp;
	}

	void mix_columns(uint8_t in[16])
	{
		for (int c = 0; c < 4; ++c)
		{
			uint8_t a0 = in[c + 0];
			uint8_t a1 = in[c + 4];
			uint8_t a2 = in[c + 8];
			uint8_t a3 = in[c + 12];

			in[c + 0]  = gf_mul2(a0) ^ gf_mul2(a1) ^ a1 ^ a2 ^ a3;
			in[c + 4]  = a0 ^ gf_mul2(a1) ^ gf_mul2(a2) ^ a2 ^ a3;
			in[c + 8]  = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul2(a3) ^ a3;
			in[c + 12] = gf_mul2(a0) ^ a0 ^ a1 ^ a2 ^ gf_mul2(a3);
		}
	}
} // namespace aes