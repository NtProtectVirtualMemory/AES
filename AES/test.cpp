#include <cstdio>
#include "crypto/AES.h"

/*
	Cipher example from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
	Reference "Appendix B - Cipher Example"

	Expected behaviour is the following:

		 Original		  Encrypted

		32 88 31 e0      39 02 dc 19
		43 5a 31 37	     25 dc 11 6a
		f6 30 98 07		 84 09 85 0b
		a8 8d a2 34		 1d fb 97 32

*/


void display_state(uint8_t* state)
{
	for (int i = 0; i < 16; ++i)
	{
		printf("0x%02X ", state[i]);
	}
	printf("\n");
}

int main()
{
	// Column Major
	uint8_t state[16] = 
	{
		0x32, 0x43, 0xf6, 0xa8,
		0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2,
		0xe0, 0x37, 0x07, 0x34
	};

	uint8_t key[16] = 
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	AES::Context ctx{ 0 };
	AES::init_context(ctx, key, AES_128);

	printf("[] Original  -> ");
	display_state(state);

	AES::encrypt_block(state, ctx);
	printf("[] Encrypted -> ");
	display_state(state);

	AES::decrypt_block(state, ctx);
	printf("[] Decrypted -> ");
	display_state(state);

	return 0;
}