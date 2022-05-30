#define LUA_LIB
#include "LuaSha1.h"
#include <cstdint>
#include <string>
extern "C"
{
	#include <lauxlib.h>
}






////////////////////////////////////////////////////////////////////////////////
// Sha1 implementation adapted from (public domain) https://github.com/983/SHA1:
class Sha1
{
private:

	void add_byte_dont_count_bits(uint8_t x)
	{
		buf[i++] = x;

		if (i >= sizeof(buf))
		{
			i = 0;
			process_block(buf);
		}
	}

	static uint32_t rol32(uint32_t x, uint32_t n)
	{
		return (x << n) | (x >> (32 - n));
	}

	static uint32_t make_word(const uint8_t * p)
	{
		return
			(static_cast<uint32_t>(p[0]) << 3 * 8) |
			(static_cast<uint32_t>(p[1]) << 2 * 8) |
			(static_cast<uint32_t>(p[2]) << 1 * 8) |
			(static_cast<uint32_t>(p[3]) << 0 * 8);
	}

	void process_block(const uint8_t * ptr)
	{
		const uint32_t c0 = 0x5a827999;
		const uint32_t c1 = 0x6ed9eba1;
		const uint32_t c2 = 0x8f1bbcdc;
		const uint32_t c3 = 0xca62c1d6;

		uint32_t a = state[0];
		uint32_t b = state[1];
		uint32_t c = state[2];
		uint32_t d = state[3];
		uint32_t e = state[4];

		uint32_t w[16];

		for (int i = 0; i < 16; i++)
		{
			w[i] = make_word(ptr + i * 4);
		}

		#define SHA1_LOAD(i) w[i & 15] = rol32(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1);
		#define SHA1_ROUND_0(v,u,x,y,z,i)              z += ((u & (x ^ y)) ^ y) + w[i & 15] + c0 + rol32(v, 5); u = rol32(u, 30);
		#define SHA1_ROUND_1(v,u,x,y,z,i) SHA1_LOAD(i) z += ((u & (x ^ y)) ^ y) + w[i & 15] + c0 + rol32(v, 5); u = rol32(u, 30);
		#define SHA1_ROUND_2(v,u,x,y,z,i) SHA1_LOAD(i) z += (u ^ x ^ y) + w[i & 15] + c1 + rol32(v, 5); u = rol32(u, 30);
		#define SHA1_ROUND_3(v,u,x,y,z,i) SHA1_LOAD(i) z += (((u | x) & y) | (u & x)) + w[i & 15] + c2 + rol32(v, 5); u = rol32(u, 30);
		#define SHA1_ROUND_4(v,u,x,y,z,i) SHA1_LOAD(i) z += (u ^ x ^ y) + w[i & 15] + c3 + rol32(v, 5); u = rol32(u, 30);

		SHA1_ROUND_0(a, b, c, d, e,  0);
		SHA1_ROUND_0(e, a, b, c, d,  1);
		SHA1_ROUND_0(d, e, a, b, c,  2);
		SHA1_ROUND_0(c, d, e, a, b,  3);
		SHA1_ROUND_0(b, c, d, e, a,  4);
		SHA1_ROUND_0(a, b, c, d, e,  5);
		SHA1_ROUND_0(e, a, b, c, d,  6);
		SHA1_ROUND_0(d, e, a, b, c,  7);
		SHA1_ROUND_0(c, d, e, a, b,  8);
		SHA1_ROUND_0(b, c, d, e, a,  9);
		SHA1_ROUND_0(a, b, c, d, e, 10);
		SHA1_ROUND_0(e, a, b, c, d, 11);
		SHA1_ROUND_0(d, e, a, b, c, 12);
		SHA1_ROUND_0(c, d, e, a, b, 13);
		SHA1_ROUND_0(b, c, d, e, a, 14);
		SHA1_ROUND_0(a, b, c, d, e, 15);
		SHA1_ROUND_1(e, a, b, c, d, 16);
		SHA1_ROUND_1(d, e, a, b, c, 17);
		SHA1_ROUND_1(c, d, e, a, b, 18);
		SHA1_ROUND_1(b, c, d, e, a, 19);
		SHA1_ROUND_2(a, b, c, d, e, 20);
		SHA1_ROUND_2(e, a, b, c, d, 21);
		SHA1_ROUND_2(d, e, a, b, c, 22);
		SHA1_ROUND_2(c, d, e, a, b, 23);
		SHA1_ROUND_2(b, c, d, e, a, 24);
		SHA1_ROUND_2(a, b, c, d, e, 25);
		SHA1_ROUND_2(e, a, b, c, d, 26);
		SHA1_ROUND_2(d, e, a, b, c, 27);
		SHA1_ROUND_2(c, d, e, a, b, 28);
		SHA1_ROUND_2(b, c, d, e, a, 29);
		SHA1_ROUND_2(a, b, c, d, e, 30);
		SHA1_ROUND_2(e, a, b, c, d, 31);
		SHA1_ROUND_2(d, e, a, b, c, 32);
		SHA1_ROUND_2(c, d, e, a, b, 33);
		SHA1_ROUND_2(b, c, d, e, a, 34);
		SHA1_ROUND_2(a, b, c, d, e, 35);
		SHA1_ROUND_2(e, a, b, c, d, 36);
		SHA1_ROUND_2(d, e, a, b, c, 37);
		SHA1_ROUND_2(c, d, e, a, b, 38);
		SHA1_ROUND_2(b, c, d, e, a, 39);
		SHA1_ROUND_3(a, b, c, d, e, 40);
		SHA1_ROUND_3(e, a, b, c, d, 41);
		SHA1_ROUND_3(d, e, a, b, c, 42);
		SHA1_ROUND_3(c, d, e, a, b, 43);
		SHA1_ROUND_3(b, c, d, e, a, 44);
		SHA1_ROUND_3(a, b, c, d, e, 45);
		SHA1_ROUND_3(e, a, b, c, d, 46);
		SHA1_ROUND_3(d, e, a, b, c, 47);
		SHA1_ROUND_3(c, d, e, a, b, 48);
		SHA1_ROUND_3(b, c, d, e, a, 49);
		SHA1_ROUND_3(a, b, c, d, e, 50);
		SHA1_ROUND_3(e, a, b, c, d, 51);
		SHA1_ROUND_3(d, e, a, b, c, 52);
		SHA1_ROUND_3(c, d, e, a, b, 53);
		SHA1_ROUND_3(b, c, d, e, a, 54);
		SHA1_ROUND_3(a, b, c, d, e, 55);
		SHA1_ROUND_3(e, a, b, c, d, 56);
		SHA1_ROUND_3(d, e, a, b, c, 57);
		SHA1_ROUND_3(c, d, e, a, b, 58);
		SHA1_ROUND_3(b, c, d, e, a, 59);
		SHA1_ROUND_4(a, b, c, d, e, 60);
		SHA1_ROUND_4(e, a, b, c, d, 61);
		SHA1_ROUND_4(d, e, a, b, c, 62);
		SHA1_ROUND_4(c, d, e, a, b, 63);
		SHA1_ROUND_4(b, c, d, e, a, 64);
		SHA1_ROUND_4(a, b, c, d, e, 65);
		SHA1_ROUND_4(e, a, b, c, d, 66);
		SHA1_ROUND_4(d, e, a, b, c, 67);
		SHA1_ROUND_4(c, d, e, a, b, 68);
		SHA1_ROUND_4(b, c, d, e, a, 69);
		SHA1_ROUND_4(a, b, c, d, e, 70);
		SHA1_ROUND_4(e, a, b, c, d, 71);
		SHA1_ROUND_4(d, e, a, b, c, 72);
		SHA1_ROUND_4(c, d, e, a, b, 73);
		SHA1_ROUND_4(b, c, d, e, a, 74);
		SHA1_ROUND_4(a, b, c, d, e, 75);
		SHA1_ROUND_4(e, a, b, c, d, 76);
		SHA1_ROUND_4(d, e, a, b, c, 77);
		SHA1_ROUND_4(c, d, e, a, b, 78);
		SHA1_ROUND_4(b, c, d, e, a, 79);

		#undef SHA1_LOAD
		#undef SHA1_ROUND_0
		#undef SHA1_ROUND_1
		#undef SHA1_ROUND_2
		#undef SHA1_ROUND_3
		#undef SHA1_ROUND_4

		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
	}

public:

	uint32_t state[5];
	uint8_t buf[64];
	uint32_t i;
	uint64_t n_bits;

	Sha1():
		i(0),
		n_bits(0)
	{
		state[0] = 0x67452301;
		state[1] = 0xefcdab89;
		state[2] = 0x98badcfe;
		state[3] = 0x10325476;
		state[4] = 0xc3d2e1f0;
	}

	Sha1 & add(uint8_t x)
	{
		add_byte_dont_count_bits(x);
		n_bits += 8;
		return *this;
	}

	Sha1 & add(char c)
	{
		return add(*reinterpret_cast<uint8_t *>(&c));
	}

	Sha1 & add(const void * data, uint32_t n)
	{
		if (!data)
		{
			return *this;
		}

		auto ptr = reinterpret_cast<const uint8_t *>(data);

		// fill up block if not full
		for (; n && i % sizeof(buf); n--)
		{
			add(*ptr++);
		}

		// process full blocks
		for (; n >= sizeof(buf); n -= sizeof(buf))
		{
			process_block(ptr);
			ptr += sizeof(buf);
			n_bits += sizeof(buf) * 8;
		}

		// process remaining part of block
		for (; n; n--)
		{
			add(*ptr++);
		}

		return *this;
	}

	Sha1 & finalize()
	{
		// hashed text ends with 0x80, some padding 0x00 and the length in bits
		add_byte_dont_count_bits(0x80);
		while (i % 64 != 56)
		{
			add_byte_dont_count_bits(0x00);
		}
		for (int j = 7; j >= 0; j--)
		{
			add_byte_dont_count_bits(static_cast<uint8_t>(n_bits >> (j * 8)));
		}

		return *this;
	}


	/** Returns the resulting hash as a hex-encoded string.
	Assumes that finalize() has been called already. */
	std::string toHexString(
		const char *alphabet = "0123456789abcdef"
	) const
	{
		std::string res;
		res.reserve(80);
		int k = 0;
		for (int i = 0; i < 5; i++)
		{
			for (int j = 7; j >= 0; j--)
			{
				res.push_back(alphabet[(state[i] >> j * 4) & 0xf]);
			}
		}
		return res;
	}
};





#ifdef _DEBUG
class SelfTest
{
	void testHashEqual(const std::string & aPlainText, const std::string & aExpectedHexHash)
	{
		Sha1 sha1;
		sha1.add(aPlainText.data(), static_cast<uint32_t>(aPlainText.size()));
		auto hash = sha1.finalize().toHexString();
		if (hash != aExpectedHexHash)
		{
			throw std::string("Hash test failure");
		}
	}

public:
	SelfTest()
	{
		testHashEqual(
			"abc",
			"a9993e364706816aba3e25717850c26c9cd0d89d"
		);
		testHashEqual(
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"a49b2446a02c645bf419f995b67091253a04a259"
		);
		testHashEqual(
			"The quick brown fox jumps over the lazy dog",
			"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
		);
	}
} gSelfTest;
#endif





static int lsl_calc(lua_State * aState)
{
	Sha1 sha1;
	int idx = 1;
	while (lua_type(aState, idx) == LUA_TSTRING)
	{
		size_t len = 0;
		auto str = lua_tolstring(aState, idx, &len);
		sha1.add(str, static_cast<uint32_t>(len));
		idx += 1;
	}
	auto hash = sha1.finalize().toHexString();
	lua_pushlstring(aState, hash.c_str(), hash.size());
	return 1;
}





static const struct luaL_Reg gLuaSha1lib[] =
{
	{"calc", &lsl_calc},
	{nullptr, nullptr},
};





extern "C" LUALIB_API int luaopen_LuaSha1(lua_State * aState)
{
	luaL_openlib(aState, "LuaSha1", gLuaSha1lib, 0);
	return 1;
}




