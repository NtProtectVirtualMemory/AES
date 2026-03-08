#pragma once
#include <cstdint>

constexpr uint8_t AES_128 = 16;
constexpr uint8_t AES_256 = 32;

namespace AES
{
	struct Context
	{
		int     Nk;
		int     Nr;
		uint8_t round_keys[240];
	};

	void init_context(Context& ctx, const uint8_t* key, int key_len);

	void encrypt_block(uint8_t block[16], const Context& ctx);
	void decrypt_block(uint8_t block[16], const Context& ctx);
} // namespace aes