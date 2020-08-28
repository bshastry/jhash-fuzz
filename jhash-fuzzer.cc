#include "jhash.h"

#include "stdlib.h"
#include "stddef.h"
#include "stdint.h"
#include <map>
#include <cassert>
#include <iostream>
#include <fstream>

using namespace std;

using HashType = unsigned;
static constexpr unsigned salt = 33554944;

namespace {

	struct SourceIpSrcDstPorts {
		unsigned Ip;
		unsigned SrcDstPorts;
	};

	static map<HashType, SourceIpSrcDstPorts> s_hashes;

	bool operator==(const SourceIpSrcDstPorts& lhs, const SourceIpSrcDstPorts& rhs)
	{
		    return lhs.Ip == rhs.Ip && lhs.SrcDstPorts == rhs.SrcDstPorts;
	}

	bool operator!=(const SourceIpSrcDstPorts& lhs, const SourceIpSrcDstPorts& rhs)
	{
		    return !(lhs == rhs);
	}

	string unsignedToIP(unsigned input)
	{
		return "Source IPv4: " + to_string(input >> 24 & 0xff)
			+ "."
			+ to_string(input >> 16 & 0xff)
			+ "."
			+ to_string(input >> 8 & 0xff)
			+ "."
			+ to_string(input & 0xff);
	}

	string unsignedToPorts(unsigned input)
	{
		return "Source port: " + to_string(input >> 16) + "\n" + "Dst port: " + to_string(input & 0xffff) + "\n";
	}
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
	// Dst port is 80 (0x50) or 443 (0x01bb)
	unsigned dstPort = (rand() % 2 == 0 ? 0x50 : 0x01bb);
	// Order is: source port (16 bits) - dst port (16 bits)
	unsigned srcDestPorts = (
			data[4] << 24 |
			data[5] << 16 |
			dstPort
	);
	unsigned h = jhash_2words(sourceIp, srcDestPorts, salt);
	auto currentInput = SourceIpSrcDstPorts{sourceIp, srcDestPorts};
	if (s_hashes.count(h))
	{
		if (s_hashes[h] != currentInput)
		{
			ofstream of("collisions.txt", ios::app);
			of << "There is a clash between the following IPv4 address/port combinations" << endl;
			of << unsignedToIP(s_hashes[h].Ip) << "\n" << unsignedToPorts(s_hashes[h].SrcDstPorts) << endl;
			of << unsignedToIP(currentInput.Ip) << "\n" << unsignedToPorts(currentInput.SrcDstPorts) << endl;
		}
		else
			return 0;
	}
	s_hashes.emplace(h, SourceIpSrcDstPorts{sourceIp, srcDestPorts});
	return 0;
}
