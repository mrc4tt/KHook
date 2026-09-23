#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <vector>

#include <khook/memory.hpp>

namespace KHook::Ranges {

struct Range {
	using Self = Range;
	Range(const Self&) = delete;
	Range& operator= (const Self&) = delete;
	Range(uintptr_t begin, uintptr_t end) : begin(begin), end(end) {
		auto len = (end - begin) + 1;
		og_bytes = new std::uint8_t[len];

		auto read = reinterpret_cast<std::uint8_t*>(begin);
		for (decltype(len) i = 0; i < len; i++, read++) {
			og_bytes[i] = *read;
		}
	}
	~Range() {
		delete[] og_bytes;
	}

    uintptr_t begin;
    uintptr_t end;
	std::uint8_t* og_bytes;
};

bool Add(std::unique_ptr<Range> range);

// Wildcard entry of a parsed sequence.
constexpr std::uint16_t WILDCARD = 0xFFFF;

// A pattern must pin down at least this many bytes. A single literal byte matches its first
// occurrence anywhere in the range, which is not a signature.
constexpr std::size_t MIN_LITERAL_BYTES = 2;

// Parses the space-separated form ("48 8B ? ?? 05"). One token is one byte: exactly two hex
// digits, or "?"/"??" for a wildcard. Leading/trailing spaces are trimmed; an empty token
// (two separators in a row) is an error, as is anything else outside that dialect, an empty
// pattern, or one with fewer than MIN_LITERAL_BYTES literal bytes.
// Returns false and leaves `out` empty on refusal; `out_error`, if given, says which rule refused it.
bool ParseSignature(const std::string& bytes, std::vector<std::uint16_t>& out, std::string* out_error = nullptr);

// 0 - If lookup fails (no match, or the pattern was refused by ParseSignature)
std::uintptr_t Lookup(std::uintptr_t start, std::size_t size, const std::string& bytes);

// Same, on an already parsed sequence, so a caller scanning several ranges parses once and
// can tell "not in the supported dialect" (ParseSignature failed) from "no match here" (0).
// Only candidates whose whole pattern fits inside [start, start + size) are tried.
std::uintptr_t Lookup(std::uintptr_t start, std::size_t size, const std::vector<std::uint16_t>& sequence);

}