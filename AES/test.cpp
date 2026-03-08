#include <cstdio>
#include <vector>
#include <random>
#include <thread>
#include <exception>

#include "crypto/AES.h"

static void display_bytes(const std::vector<uint8_t>& data)
{
	for (size_t i = 0; i < data.size(); i++)
	{
		printf("%02X ", data[i]);
	}

	printf("\n");
}

static void set_key(uint8_t* key)
{
	static std::random_device gen;
	static std::uniform_int_distribution<int> dist(0, 255);

	for (int i = 0; i < 32; i++)
	{
		key[i] = dist(gen);
	}
}

static void set_iv(uint8_t* iv)
{
	static std::random_device gen;
	static std::uniform_int_distribution<int> dist(0, 255);

	for (int i = 0; i < 16; i++)
	{
		iv[i] = dist(gen);
	}
}

static void send_message(std::vector<uint8_t> buffer)
{
	uint8_t iv[16]{ 0 };
	set_iv(iv);

	uint8_t key[32]{ 0 };
	set_key(key);

	AES::Context ctx{};
	AES::init_context(ctx, key, AES_256);

	try
	{
		AES::encrypt(buffer.data(), buffer.size(), ctx, AES::Mode::CBC, iv);
		printf("\n* Encrypted:\n%s\n-> ", buffer.data());
		display_bytes(buffer);

		AES::decrypt(buffer.data(), buffer.size(), ctx, AES::Mode::CBC, iv);
		printf("\n* Decrypted:\n%s\n-> ", buffer.data());
		display_bytes(buffer);

	}
	catch (const std::exception& e)
	{
		printf("Exception: %s\n", e.what());
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
	system("cls");
}

int main()
{
	while (true)
	{
		char input[1024];
		printf("message: ");
		fgets(input, sizeof(input), stdin);

		size_t len = strlen(input);
		if (input[len - 1] == '\n')
		{
			input[len - 1] = 0;
		}
		len = strlen(input);

		size_t padded_size = ((len + 15) / 16) * 16;
		std::vector<uint8_t> buffer(padded_size);

		memcpy(buffer.data(), input, len);
		for (size_t i = len; i < padded_size; i++)
		{
			buffer[i] = 0;
		}

		send_message(buffer);
	}

	return 0;
}