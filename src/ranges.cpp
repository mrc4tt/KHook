#include "ranges.hpp"

#include <vector>
#include <algorithm>
#include <shared_mutex>
#include <mutex>
#include <cstring>
#include <iostream>
#include <iomanip>

namespace KHook::Ranges {

std::vector<std::unique_ptr<Range>> g_ranges;
std::shared_mutex g_mutex;

bool Add(std::unique_ptr<Range> range) {
	std::unique_lock lock(g_mutex);

	if (range->begin > range->end) {
		return false;
	}

	auto it = std::lower_bound(
	g_ranges.begin(),
	g_ranges.end(),
	range->begin,
	[](const std::unique_ptr<Range>& r, std::uintptr_t value) {
		return r->begin < value;
	});

    // Check overlap with previous range
    if (it != g_ranges.begin()) {
        auto prev = std::prev(it);

        if (range->begin <= (*prev)->end) {
			return false;
		}
    }

    // Check overlap with next range
    if (it != g_ranges.end()) {
        if (range->end >= (*it)->begin) {
			return false;
		}
    }

    g_ranges.insert(it, std::move(range));
    return true;
}

static int HexDigit(const char c) {
	return ('0' <= c && c <= '9') ? c - '0'
	: ('a' <= c && c <= 'f') ? 10 + (c - 'a')
	: ('A' <= c && c <= 'F') ? 10 + (c - 'A') : -1;
}

static bool Refuse(std::vector<std::uint16_t>& out, std::string* out_error, std::string message) {
	out.clear();
	if (out_error) {
		*out_error = std::move(message);
	}
	return false;
}

bool ParseSignature(const std::string& bytes, std::vector<std::uint16_t>& out, std::string* out_error) {
	out.clear();

	const auto first = bytes.find_first_not_of(' ');
	if (first == std::string::npos) {
		return Refuse(out, out_error, "empty pattern");
	}
	const auto last = bytes.find_last_not_of(' ');

	std::size_t literals = 0;
	for (std::size_t pos = first; pos <= last;) {
		auto end = bytes.find(' ', pos);
		if (end == std::string::npos || end > last) {
			end = last + 1;
		}

		const auto token = bytes.substr(pos, end - pos);
		if (token.empty()) {
			return Refuse(out, out_error, "empty token at offset " + std::to_string(pos));
		}

		if (token == "?" || token == "??") {
			out.push_back(WILDCARD);
		} else if (token.size() == 2 && HexDigit(token[0]) != -1 && HexDigit(token[1]) != -1) {
			out.push_back(static_cast<std::uint16_t>(HexDigit(token[0]) * 16 + HexDigit(token[1])));
			literals++;
		} else {
			return Refuse(out, out_error, "invalid token \"" + token + "\" at offset " + std::to_string(pos));
		}

		pos = end + 1;
	}

	if (literals < MIN_LITERAL_BYTES) {
		return Refuse(out, out_error, "pattern has " + std::to_string(literals) + " literal byte(s), at least "
			+ std::to_string(MIN_LITERAL_BYTES) + " required");
	}

	return true;
}

std::uintptr_t Lookup(std::uintptr_t start, std::size_t size, const std::string& bytes) {
	std::vector<std::uint16_t> sequence;
	if (!ParseSignature(bytes, sequence)) {
		return 0;
	}
	return Lookup(start, size, sequence);
}

std::uintptr_t Lookup(std::uintptr_t start, std::size_t size, const std::vector<std::uint16_t>& sequence) {
	if (sequence.empty() || size < sequence.size()) {
		return 0;
	}

	std::shared_lock lock(g_mutex);

	auto it = std::lower_bound(
	g_ranges.begin(),
	g_ranges.end(),
	start,
	[](const std::unique_ptr<Range>& r, std::uintptr_t address) {
		return r->end < address;
	});

	const auto& it_end = g_ranges.end();
	for (auto lookup = start, lookup_end = start + size - sequence.size() + 1; lookup < lookup_end; lookup++) {
		// Move the iterator further until we intersect again
		while (it != it_end && (*it)->end < lookup) {
			it++;
		}

		auto read_it = it;
		bool found = true;
		for (std::size_t i = 0; i < sequence.size() && found; i++) {
			if (sequence[i] == 0xFFFF) {
				// Wildcard, skip
				continue;
			}

			auto read = lookup + i;

			// Move the iterator further until we intersect again
			while (read_it != it_end && (*read_it)->end < read) {
				read_it++;
			}

			if (it_end != read_it) {
				if (read >= (*read_it)->begin && read <= (*read_it)->end) {
					auto diff = read - (*read_it)->begin;
					read = reinterpret_cast<std::uintptr_t>(&((*read_it)->og_bytes[diff]));
				}
			}

			// Ensure bytes are matching 
			found &= (*reinterpret_cast<std::uint8_t*>(read) == sequence[i]);
		}

		if (found) {
			return lookup;
		}
	}

	// Failure
	return 0;
}

}