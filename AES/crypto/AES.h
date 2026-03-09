#pragma once
#include <cstdint>

constexpr uint8_t AES_128 = 16;
constexpr uint8_t AES_256 = 32;

namespace AES
{
	enum class Mode
	{
		ECB,
		CBC
	};

	struct Context
	{
		int     Nk;
		int     Nr;
		uint8_t round_keys[240];
	};

	void init_context(Context& ctx, const uint8_t* key, int key_len);

	void encrypt(uint8_t* data, size_t len, const Context& ctx, Mode mode, const uint8_t iv[16] = nullptr);
	void decrypt(uint8_t* data, size_t len, const Context& ctx, Mode mode, const uint8_t iv[16] = nullptr);

} // namespace aes