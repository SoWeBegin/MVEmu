#ifndef MAIN_ITEM_SERIALINFO_H
#define MAIN_ITEM_SERIALINFO_H

#include <cstdint>
#include <corecrt.h>
#include <ctime>
#include <compare>

namespace Main
{
	namespace Structures
	{
#pragma pack(push, 1)
		struct ItemSerialInfo
		{
			std::uint64_t itemNumber : 16 = 0;
			std::uint64_t itemOrigin : 8 = 0; // 0 = shop, 1 = gift, 4 = event, 5 = dev tool, 6 = web shop, 8 = gm spawn
			std::uint64_t m_serverId : 8 = 0;
			std::uint64_t itemCreationDate : 32 = 0;
			
			/*
			std::uint64_t itemNumber : 20 = 0;
			std::uint64_t m_serverId : 4 = 0;
			std::uint64_t unknown : 4 = 0;
			std::uint64_t itemOrigin : 4 = 0; 
			std::uint64_t itemCreationDate : 32 = 0;
			*/

			auto operator<=>(const ItemSerialInfo&) const = default;
		};
#pragma pack(pop)
	}
}

#endif