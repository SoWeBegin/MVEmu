
// DELETE THIS LINKER ERRORS?
#include <iostream>
#include <Windows.h>

#include "../../include/Utils/Parser.h"



namespace Common
{
	namespace Parser
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

		void printTcpHeader(Common::Protocol::TcpHeader header)
		{
			std::cout << "[Actual Size:" << header.getSize() << "] \n";
			std::cout << "[Bogus/Padding:" << header.getBogus() << "] \n";
			std::cout << "[SessionID:" << header.getSessionId() << "] \n";
			std::cout << "[Crypt:" << header.getCrypt() << "] \n";
		}

		void printCommandHeader(Common::Protocol::CommandHeader command)
		{
			std::cout << "[Mission:" << command.getMission() << "] \n";
			std::cout << "[Order:" << command.getOrder() << "] \n";
			std::cout << "[Extra:" << command.getExtra() << "] \n";
			std::cout << "[Option:" << command.getOption() << "] \n";
			std::cout << "[Padding:" << command.getBogus() << "] \n";
		}

		void parseCommandHeader(std::uint8_t* data)
		{
			SetConsoleTextAttribute(hConsole, 3);
			std::cout << "Command Header:\n";
			std::uint32_t actualCommand; memcpy(&actualCommand, data + 4, sizeof(uint32_t));
			Common::Protocol::CommandHeader command(actualCommand);
			SetConsoleTextAttribute(hConsole, 5);
			std::cout << "[Mission:" << command.getMission() << "] \n";
			std::cout << "[Order:" << command.getOrder() << "] \n";
			std::cout << "[Extra:" << command.getExtra() << "] \n";
			std::cout << "[Option:" << command.getOption() << "] \n";
			std::cout << "[Padding:" << command.getBogus() << "] \n";
			SetConsoleTextAttribute(hConsole, 7);
		}

		std::pair<std::size_t, uint32_t> parseTcpHeader(std::uint8_t* data) 
		{
			SetConsoleTextAttribute(hConsole, 3);
			std::cout << "\nTcp Header: \n";
			std::uint32_t header;
			memcpy(&header, data, sizeof(std::uint32_t));
			Common::Protocol::TcpHeader parsedHeader(header);
			SetConsoleTextAttribute(hConsole, 5);
			std::cout << "[Actual Size:" << parsedHeader.getSize() << "] \n";
			std::cout << "[Bogus/Padding:" << parsedHeader.getBogus() << "] \n";
			std::cout << "[SessionID:" << parsedHeader.getSessionId() << "] \n";
			std::cout << "[Crypt:" << parsedHeader.getCrypt() << "] \n";
			std::size_t sizeRetrievedFromTcpHeader = parsedHeader.getSize();
			std::uint32_t toCrypt = parsedHeader.getCrypt();

			SetConsoleTextAttribute(hConsole, 7);
			return std::pair{ sizeRetrievedFromTcpHeader, toCrypt };
		}

		void parseDecryptedPacket(std::size_t len, std::uint8_t* data) 
		{
			parseCommandHeader(data);
			SetConsoleTextAttribute(hConsole, 3);
			std::cout << "Decrypted Packet: \n";
			SetConsoleTextAttribute(hConsole, 7);
			for (std::size_t i = 0; i < len; ++i) 
			{
				printf("%02X ", static_cast<uint8_t>(data[i]));
			}
			std::cout << "\n";
		}

		void parse(std::uint8_t* data, std::size_t len, std::size_t port, const std::string& origin, const std::string& to, std::int32_t cryptKey, bool first)
		{
			SetConsoleTextAttribute(hConsole, 2);
			std::cout << "\n[" << origin << "->" << to << "]";
			SetConsoleTextAttribute(hConsole, 3);
			
			SetConsoleTextAttribute(hConsole, 5);
			std::cout << "[Size:" << len << "] \n";


			Common::Cryptography::Crypt cryptDefault(0);
			Common::Cryptography::Crypt userCrypt(cryptKey);

			cryptDefault.RC5Decrypt32(data, data, 4);
			std::uint32_t actualData;
			memcpy(&actualData, data, sizeof(std::uint32_t));
			SetConsoleTextAttribute(hConsole, 5);

			const Common::Protocol::TcpHeader header(actualData);
			printTcpHeader(header);

			const int toCrypt = header.getCrypt();
			const std::size_t actualSize = header.getSize();
			cryptDefault.RC5Encrypt32(data, data, 4);

			SetConsoleTextAttribute(hConsole, 7);
			for (std::size_t i = 0; i < actualSize; ++i)
			{
				printf("%02X ", static_cast<std::uint8_t>(data[i]));
			}
			std::cout << '\n';

			Common::Cryptography::Crypt givenCrypt(cryptKey);
			if (first)
			{
				cryptDefault.RC5Decrypt32(data, data, 4);
				std::cout << "Decrypted Packet: " << std::endl;
				std::cout << std::endl;
				for (std::size_t i = 0; i < actualSize; ++i)
				{
					printf("%02X ", static_cast<std::uint8_t>(data[i]));
				}
				givenCrypt.RC5Encrypt32(data, data, 4);
				std::uint32_t actualCommand;
				memcpy(&actualCommand, data + 4, sizeof(std::uint32_t));
				printCommandHeader(Common::Protocol::CommandHeader{ actualCommand });
				printf("\n");
				return;
			}
			
			else {
				switch (toCrypt) {
				case 0: // no crypt
					parseDecryptedPacket(actualSize, data);
					break;

				case 1:
					cryptDefault.RC5Decrypt64(data + 4, data + 4, static_cast<int>(actualSize - 4));
					parseDecryptedPacket(actualSize, data);
					cryptDefault.RC5Encrypt64(data + 4, data + 4, static_cast<int>(actualSize - 4));
					break;

				case 3:
					cryptDefault.RC6Decrypt128(data + 4, data + 4, static_cast<int>(actualSize - 4));
					parseDecryptedPacket(actualSize, data);
					cryptDefault.RC6Encrypt128(data + 4, data + 4, static_cast<int>(actualSize - 4));
					break;

				case 2:
					userCrypt.RC5Decrypt64(data + 4, data + 4, static_cast<int>(actualSize - 4));
					parseDecryptedPacket(actualSize, data);
					userCrypt.RC5Encrypt64(data + 4, data + 4, static_cast<int>(actualSize - 4));
					break;

				case 4:
					userCrypt.RC6Decrypt128(data + 4, data + 4, static_cast<int>(actualSize - 4));
					parseDecryptedPacket(actualSize, data);
					userCrypt.RC6Encrypt128(data + 4, data + 4, static_cast<int>(actualSize - 4));
					break;

				default:
					std::cerr << "Invalid crypt found!\n";
					break;
				}
			}
		}

		void parse_cast(std::uint8_t* data, std::size_t len, std::size_t port, const std::string& origin, const std::string& to)
		{
			std::uint32_t actualData;
			memcpy(&actualData, data, sizeof(std::uint32_t));

			const Common::Protocol::TcpHeader header(actualData);

			std::uint32_t actualCommand;
			memcpy(&actualCommand, data + 4, sizeof(std::uint32_t));
			Common::Protocol::CommandHeader commandHeader{ actualCommand };

			if (commandHeader.getOrder() == 322 or commandHeader.getOrder() == 281) return; // Avoid printing the position

			SetConsoleTextAttribute(hConsole, 2);
			std::cout << "\n[" << origin << "->" << to << "]";
			SetConsoleTextAttribute(hConsole, 3);
			std::cout << "[CastServer:" << port << "]";
			SetConsoleTextAttribute(hConsole, 5);
			std::cout << "[Size:" << len << "] \n";
			SetConsoleTextAttribute(hConsole, 5);

			printTcpHeader(header);

			SetConsoleTextAttribute(hConsole, 7);
			for (std::size_t i = 0; i < header.getSize(); ++i)
			{
				printf("%02X ", static_cast<std::uint8_t>(data[i]));
			}
			std::cout << '\n';

			printCommandHeader(Common::Protocol::CommandHeader{ actualCommand });
		}
	}
}

