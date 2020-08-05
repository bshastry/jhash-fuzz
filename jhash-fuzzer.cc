#include "jhash.h"

#include "stdlib.h"
#include "stddef.h"
#include "stdint.h"
#include <map>
#include <cassert>
#include <iostream>
#include <fstream>

using namespace std;

struct SourceIpPort {
	unsigned Ip;
	unsigned Port;
};

bool operator==(const SourceIpPort& lhs, const SourceIpPort& rhs)
{
	    return lhs.Ip == rhs.Ip && lhs.Port == rhs.Port;
}

bool operator!=(const SourceIpPort& lhs, const SourceIpPort& rhs)
{
	    return !(lhs == rhs);
}

using HashType = unsigned;

static map<HashType, SourceIpPort> s_hashes;
static constexpr unsigned salt = 33554944;

string unsignedToIP(unsigned input)
{
	return to_string(input >> 24 & 0xff)
		+ "."
		+ to_string(input >> 16 & 0xff)
		+ "."
		+ to_string(input >> 8 & 0xff)
		+ "."
		+ to_string(input & 0xff);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	if (len != 6)
		return 0;

	unsigned sourceIp = (
			data[0] << 24 |
			data[1] << 16 |
			data[2] << 8 |
			data[3]
			);
	unsigned sourcePort = (
			data[4] << 8 |
			data[5]
			);
	unsigned h = jhash_2words(sourceIp, sourcePort, salt);
	auto currentInput = SourceIpPort{sourceIp, sourcePort};
	if (s_hashes.count(h))
	{
		if (s_hashes[h] != currentInput)
		{
			ofstream of("collisions.txt", ios::app);
			of << "There is a clash between the following IPv4 address/port combinations" << endl;
			of << unsignedToIP(s_hashes[h].Ip) << ":" << s_hashes[h].Port << endl;
			of << unsignedToIP(currentInput.Ip) << ":" << currentInput.Port << endl;
			assert(false);
		}
		else
			return 0;
	}
	s_hashes.emplace(h, SourceIpPort{sourceIp, sourcePort});
	return 0;
}
