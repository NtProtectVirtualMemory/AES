#include "AES.h"
#include "tables.h"
#include "utils.h"

#include <cstdint>
#include <stdexcept>

namespace AES 
{
	static void add_key(uint8_t in[16], const uint8_t key[16])
	{
		for (int i{ 0 }; i < 16; ++i)
		{
			in[i] ^= key[i];
		}
	}

	static void sub_bytes(uint8_t in[16])
	{
		for (int i{ 0 }; i < 16; ++i)
		{
			in[i] = sbox(in[i]);
		}
	}

	static void inv_sub_bytes(uint8_t in[16])
	{
		for (int i = 0; i < 16; ++i)
			in[i] = inv_sbox(in[i]);           
	}

	static void shift_rows(uint8_t s[16])
	{
		uint8_t temp;

		// Row 1: left rotate by 1
		temp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = temp;

		// Row 2: left rotate by 2
		temp = s[2]; s[2] = s[10]; s[10] = temp;
		temp = s[6]; s[6] = s[14]; s[14] = temp;

		// Row 3: left rotate by 3
		temp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = temp;
	}

	static void inv_shift_rows(uint8_t s[16])
	{
		uint8_t temp;

		// Row 1: right rotate by 1o
		temp = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = temp;

		// Row 2: right rotate by 2
		temp = s[2]; s[2] = s[10]; s[10] = temp;
		temp = s[6]; s[6] = s[14]; s[14] = temp;

		// Row 3: right rotate by 3
		temp = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = temp;
	}

	static void mix_columns(uint8_t in[16])
	{
		for (int c = 0; c < 4; ++c)
		{
			uint8_t a0 = in[c * 4 + 0];
			uint8_t a1 = in[c * 4 + 1];
			uint8_t a2 = in[c * 4 + 2];
			uint8_t a3 = in[c * 4 + 3];

			in[c * 4 + 0] = gf_mul2(a0) ^ gf_mul2(a1) ^ a1 ^ a2 ^ a3;
			in[c * 4 + 1] = a0 ^ gf_mul2(a1) ^ gf_mul2(a2) ^ a2 ^ a3;
			in[c * 4 + 2] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul2(a3) ^ a3;
			in[c * 4 + 3] = gf_mul2(a0) ^ a0 ^ a1 ^ a2 ^ gf_mul2(a3);
		}
	}

	static void inv_mix_columns(uint8_t in[16])
	{
		for (int c = 0; c < 4; ++c)
		{
			uint8_t a0 = in[c * 4 + 0], a1 = in[c * 4 + 1];
			uint8_t a2 = in[c * 4 + 2], a3 = in[c * 4 + 3];

			in[c * 4 + 0] = gf_mul(0x0e, a0) ^ gf_mul(0x0b, a1) ^ gf_mul(0x0d, a2) ^ gf_mul(0x09, a3);
			in[c * 4 + 1] = gf_mul(0x09, a0) ^ gf_mul(0x0e, a1) ^ gf_mul(0x0b, a2) ^ gf_mul(0x0d, a3);
			in[c * 4 + 2] = gf_mul(0x0d, a0) ^ gf_mul(0x09, a1) ^ gf_mul(0x0e, a2) ^ gf_mul(0x0b, a3);
			in[c * 4 + 3] = gf_mul(0x0b, a0) ^ gf_mul(0x0d, a1) ^ gf_mul(0x09, a2) ^ gf_mul(0x0e, a3);
		}
	}

	static void expand_key(Context& ctx, const uint8_t* key)
	{
		const int total_words = (ctx.Nr + 1) * 4;
		for (int i = 0; i < ctx.Nk * 4; ++i)
		{
			ctx.round_keys[i] = key[i];
		}

		uint8_t temp[4]{ 0 };
		for (int i = ctx.Nk; i < total_words; ++i)
		{
			const int prev = (i - 1) * 4;
			temp[0] = ctx.round_keys[prev + 0]; temp[1] = ctx.round_keys[prev + 1];
			temp[2] = ctx.round_keys[prev + 2]; temp[3] = ctx.round_keys[prev + 3];

			if (i % ctx.Nk == 0)
			{
				rot_word(temp);
				sub_word(temp);
				temp[0] ^= rcon(i / ctx.Nk);
			}
			else if (ctx.Nk == 8 && i % ctx.Nk == 4)
			{
				sub_word(temp);
			}

			const int base = i * 4;
			const int base_nk = (i - ctx.Nk) * 4;
			ctx.round_keys[base + 0] = ctx.round_keys[base_nk + 0] ^ temp[0];
			ctx.round_keys[base + 1] = ctx.round_keys[base_nk + 1] ^ temp[1];
			ctx.round_keys[base + 2] = ctx.round_keys[base_nk + 2] ^ temp[2];
			ctx.round_keys[base + 3] = ctx.round_keys[base_nk + 3] ^ temp[3];
		}
	}

	void encrypt_block(uint8_t block[16], const Context& ctx)
	{
		add_key(block, ctx.round_keys);

		for (int round = 1; round < ctx.Nr; ++round)
		{
			sub_bytes(block);
			shift_rows(block);
			mix_columns(block);
			add_key(block, ctx.round_keys + round * 16);
		}

		sub_bytes(block);
		shift_rows(block);
		add_key(block, ctx.round_keys + ctx.Nr * 16);
	}

	void decrypt_block(uint8_t block[16], const Context& ctx)
	{
		add_key(block, ctx.round_keys + ctx.Nr * 16);

		for (int round = ctx.Nr - 1; round >= 1; --round)
		{
			inv_shift_rows(block);
			inv_sub_bytes(block);
			add_key(block, ctx.round_keys + round * 16);
			inv_mix_columns(block);
		}

		inv_shift_rows(block);
		inv_sub_bytes(block);
		add_key(block, ctx.round_keys);
	}

	void init_context(Context& ctx, const uint8_t* key, int key_len)
	{
		ctx.Nk = key_len / 4;
		ctx.Nr = ctx.Nk + 6;
		expand_key(ctx, key);
	}

} // namespace aes