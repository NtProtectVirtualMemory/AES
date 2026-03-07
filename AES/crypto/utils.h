#pragma once
#include <cstdint>
#include "tables.h"

namespace aes 
{
	static inline uint8_t gf_mul2(uint8_t a)
	{
		return (a << 1) ^ ((a >> 7) ? 0x1b : 0x00);
	}
	
} // namespace aes