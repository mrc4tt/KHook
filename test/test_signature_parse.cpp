#include <gtest/gtest.h>
#include <khook.hpp>

#include "ranges.hpp"

#include <cstdint>
#include <string>
#include <vector>

using KHook::Ranges::Lookup;
using KHook::Ranges::ParseSignature;
using KHook::Ranges::WILDCARD;

namespace {

// A stray 0x2A in front of the "function", which is where a pattern degraded to its last
// byte used to land.
struct Image {
	std::vector<std::uint8_t> bytes = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0xCC, 0xCC,
		0x55, 0x48, 0x89, 0xE5, 0x2A, 0x10,
		0xCC, 0xCC, 0xCC, 0xCC,
	};
	static constexpr std::size_t function = 10;

	std::uintptr_t start() const { return reinterpret_cast<std::uintptr_t>(bytes.data()); }
	std::uintptr_t lookup(const std::string& pattern) const { return Lookup(start(), bytes.size(), pattern); }
};

bool Refused(const std::string& pattern, std::string* error = nullptr) {
	std::vector<std::uint16_t> out = { 1, 2, 3 };
	const auto ok = ParseSignature(pattern, out, error);
	return !ok && out.empty();
}

} // namespace

TEST(SignatureParse, ParsesIdaStyle) {
	std::vector<std::uint16_t> out;
	ASSERT_TRUE(ParseSignature("55 48 ? ?? e5", out));
	EXPECT_EQ(out, (std::vector<std::uint16_t>{ 0x55, 0x48, WILDCARD, WILDCARD, 0xE5 }));
}

TEST(SignatureParse, TrimsEnds) {
	std::vector<std::uint16_t> out;
	ASSERT_TRUE(ParseSignature("  55 48 89  ", out));
	EXPECT_EQ(out, (std::vector<std::uint16_t>{ 0x55, 0x48, 0x89 }));
}

TEST(SignatureParse, RefusesCodeStyle) {
	// Used to parse as the single byte 2A.
	std::string error;
	EXPECT_TRUE(Refused("\\x55\\x48\\x89\\xE5\\x2A", &error));
	EXPECT_NE(error.find("invalid token"), std::string::npos) << error;
}

TEST(SignatureParse, RefusesLongToken) {
	// Used to parse as its last two characters, "48".
	EXPECT_TRUE(Refused("5548 89 E5"));
}

TEST(SignatureParse, RefusesEmptyToken) {
	std::string error;
	EXPECT_TRUE(Refused("55  48", &error));
	EXPECT_NE(error.find("empty token"), std::string::npos) << error;
}

TEST(SignatureParse, RefusesEmptyAndBlank) {
	EXPECT_TRUE(Refused(""));
	EXPECT_TRUE(Refused("   "));
}

TEST(SignatureParse, RefusesSingleCharacter) {
	// Used to read c_string[-1].
	EXPECT_TRUE(Refused("5"));
	EXPECT_TRUE(Refused("?"));
}

TEST(SignatureParse, RefusesTooFewLiterals) {
	std::string error;
	EXPECT_TRUE(Refused("2A", &error));
	EXPECT_NE(error.find("literal"), std::string::npos) << error;
	EXPECT_TRUE(Refused("? ? 2A ?"));
	EXPECT_FALSE(Refused("? 55 ? 48"));
}

TEST(SignatureLookup, FindsFunction) {
	const Image image;
	EXPECT_EQ(image.lookup("55 48 89 E5 ? 10"), image.start() + Image::function);
}

TEST(SignatureLookup, RefusedPatternDoesNotMatchStray2A) {
	const Image image;
	EXPECT_EQ(image.lookup("\\x55\\x48\\x89\\xE5\\x2A"), 0u);
	EXPECT_EQ(image.lookup("2A"), 0u);
	EXPECT_EQ(image.lookup(""), 0u);
}

TEST(SignatureLookup, StaysInsideRange) {
	const Image image;
	// The match is at +10 and is 6 bytes long; a range ending one byte short must not find it
	// by reading past its end.
	EXPECT_EQ(Lookup(image.start(), Image::function + 5, std::string("55 48 89 E5 ? 10")), 0u);
	EXPECT_EQ(Lookup(image.start(), Image::function + 6, std::string("55 48 89 E5 ? 10")), image.start() + Image::function);
	EXPECT_EQ(Lookup(image.start(), 3, std::string("55 48 89 E5 ? 10")), 0u);
}

TEST(SignatureLookup, SequenceOverloadParsesOnce) {
	const Image image;
	std::vector<std::uint16_t> sequence;
	ASSERT_TRUE(ParseSignature("55 48 89 E5", sequence));
	EXPECT_EQ(Lookup(image.start(), image.bytes.size(), sequence), image.start() + Image::function);
	EXPECT_EQ(Lookup(image.start(), Image::function, sequence), 0u);
}
