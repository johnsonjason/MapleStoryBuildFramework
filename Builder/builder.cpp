// MSACBuilder.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <unordered_map>

#define FILL_VALUE 0
#define MAX_URL 768

enum class ms_file_options : std::size_t
{
	undefined,
	version_62,
	version_83
};

// Obfuscation/encoding offsets
static const std::vector<std::pair<std::size_t, std::size_t>> pair_ptr_set =
{
	{ 0x274F56, 0x50 }
};

// Map each version to a repository string
// version enum = <repository url input>
static const std::unordered_map<ms_file_options, std::size_t> version_repository_map =
{
	{ ms_file_options::version_62, 0x6B0},
	{ ms_file_options::version_83, FILL_VALUE}
};

// Map each version to a digital file signature
// version enum = version signature/code to check for
static const std::unordered_map<ms_file_options, std::pair<std::size_t, std::uint8_t>> version_signature_map =
{
	{ ms_file_options::version_62, { 0x20EA30, 0xE8 } },
	{ ms_file_options::version_83, { FILL_VALUE, FILL_VALUE } }
};

// Map each version to a shellcode pairing
// version enum = <address<code>>
static const std::unordered_map<ms_file_options, std::pair<std::size_t, std::vector<std::uint8_t>>> version_code_map =
{
	{ ms_file_options::version_62, 
		{ 0x46EC24,
			{ 
				0x68, 0xA0, 0x06, 0x40, 0x00,
				0xFF, 0x15, 0x30, 0x81, 0x8E, 0x00,
				0xE9, 0xAB, 0xDD, 0x00, 0x00 
			}		
		} 
	},
	{ ms_file_options::version_83, { FILL_VALUE, { FILL_VALUE } } }
};

// Map each version to an entry point
// version enum = entry point
static const std::unordered_map<ms_file_options, std::uint32_t> version_ep_map =
{
	{ ms_file_options::version_62, 0x0046EC24 },
	{ ms_file_options::version_83, FILL_VALUE }
};

static const std::unordered_map<ms_file_options, std::size_t> version_package_map =
{
	{ ms_file_options::version_62, 0x6A0 },
	{ ms_file_options::version_83, FILL_VALUE }
};

static const std::vector<std::uint8_t> enc_wsablock = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

static const std::unordered_map<std::string, std::pair<std::size_t, std::vector<std::uint8_t>>> version_rt_encblocks =
{
	{ "v62wsa", { 0x00274F50, enc_wsablock } }
};

static volatile std::uint8_t encoding_status = 0;

static void close_valid_handle(const HANDLE file)
{
	if (file != INVALID_HANDLE_VALUE && file != NULL)
	{
		CloseHandle(file);
	}
}

static std::uint8_t check_encoding(ms_file_options version, std::uint8_t flag)
{
	if (version == ms_file_options::version_62)
	{
		if (flag == 0xAC)
		{
			return 2;
		}
		else if (flag == 0x56)
		{
			return 1;
		}
	}
	else if (version == ms_file_options::version_83)
	{
		return 0;
	}
	return 0;
}

static std::vector<std::uint8_t>& encode_block(std::vector<std::uint8_t>& data_stream)
{
	for (std::uint8_t& byte : data_stream)
	{
		byte = ((~byte) + 3);
	}
	return data_stream;
}

static void write_file_point(const HANDLE file, const std::size_t file_start, const std::vector<std::uint8_t>& data_stream)
{
	unsigned long bytes_written;
	SetFilePointer(file, file_start, nullptr, FILE_BEGIN);
	WriteFile(file, data_stream.data(), data_stream.size(), &bytes_written, nullptr);
}

static void get_file_data(const HANDLE file, std::vector<std::uint8_t>& data_stream, 
	const std::pair<const std::size_t, const std::size_t>& ptr_set)
{
	unsigned long bytes_read;
	SetFilePointer(file, ptr_set.first, nullptr, FILE_BEGIN);
	ReadFile(file, &data_stream[0], data_stream.size(), &bytes_read, nullptr);
}

static void set_file_obfuscation(ms_file_options version, const HANDLE file)
{
	for (const std::pair<const std::size_t, const std::size_t>& ptr_set : pair_ptr_set)
	{
		std::vector<std::uint8_t> data_stream;
		data_stream.resize(ptr_set.second);

		get_file_data(file, data_stream, ptr_set);
		if (version == ms_file_options::version_62)
		{
			if (encoding_status == 0)
			{
				encoding_status = check_encoding(version, data_stream[0]);
			}
			if (encoding_status == 2)
			{
				std::cout << "Decoding block... ";
				write_file_point(file, ptr_set.first, encode_block(data_stream));
				std::cout << "done\n";
			}
			else if (encoding_status == 1)
			{
				std::cout << "Block encoding attempt... ";
				write_file_point(file, ptr_set.first, encode_block(data_stream));
				std::cout << "done\n";
			}
		}
	}
}

static bool check_version(const HANDLE file, const ms_file_options version)
{
	unsigned long bytes_read;
	std::uint8_t data;

	SetFilePointer(file, version_signature_map.at(version).first, nullptr, FILE_BEGIN);
	ReadFile(file, &data, sizeof(data), &bytes_read, nullptr);

	if (data == version_signature_map.at(version).second)
	{
		return true;
	}
	return false;
}

static void set_ep(const ms_file_options version, void* data_map)
{
	PIMAGE_DOS_HEADER img_dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(data_map);
	PIMAGE_NT_HEADERS img_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(img_dos_headers) + img_dos_headers->e_lfanew);
	img_nt_headers->OptionalHeader.AddressOfEntryPoint = version_ep_map.at(version);
}

static void set_shellcode(const ms_file_options version, std::vector<std::string>& keys, std::size_t data_map)
{
	void* _ptrseek = reinterpret_cast<void*>(data_map + version_code_map.at(version).first);
	std::vector<std::uint8_t> code = version_code_map.at(version).second;
	std::memcpy(_ptrseek, code.data(), code.size());

	try
	{
		for (std::string& key : keys)
		{
			std::pair<std::size_t, std::vector<std::uint8_t>> enc_block = version_rt_encblocks.at(key);
			_ptrseek = reinterpret_cast<void*>(data_map + enc_block.first);
			std::memcpy(_ptrseek, enc_block.second.data(), enc_block.second.size());
		}
	}
	catch (std::out_of_range& e)
	{
		std::cout << "Map exception occurred." << std::endl;
	}
	return;
}

static ms_file_options set_file_magic(const HANDLE file)
{
	HANDLE map_object = CreateFileMappingW(file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (map_object == nullptr)
	{
		return ms_file_options::undefined;
	}

	void* map_addr = MapViewOfFileEx(map_object, FILE_MAP_ALL_ACCESS, 0, 0, 0, nullptr);
	if (map_addr == nullptr)
	{
		return ms_file_options::undefined;
	}

	std::vector<std::string> keys = { "v62wsa" };
	if (check_version(file, ms_file_options::version_62))
	{
		set_ep(ms_file_options::version_62, map_addr);
		set_shellcode(ms_file_options::version_62, keys, reinterpret_cast<std::size_t>(map_addr));

		UnmapViewOfFile(map_addr);
		close_valid_handle(map_object);

		return ms_file_options::version_62;
	}
	else if (check_version(file, ms_file_options::version_83))
	{
		set_ep(ms_file_options::version_83, map_addr);
		set_shellcode(ms_file_options::version_83, keys, reinterpret_cast<std::size_t>(map_addr));

		UnmapViewOfFile(map_addr);
		close_valid_handle(map_object);

		return ms_file_options::version_83;
	}

	UnmapViewOfFile(map_addr);
	close_valid_handle(map_object);
	return ms_file_options::undefined;
}

static void set_file_string(const HANDLE file, const ms_file_options version, const std::string& repository, const std::string& acpackage)
{
	unsigned long bytes_written;
	std::vector<unsigned char> zero_block;
	if (version == ms_file_options::version_62)
	{
		zero_block.resize(128);
		std::fill(zero_block.begin(), zero_block.end(), 0);
	}
	else if (version == ms_file_options::version_83)
	{
		zero_block.resize(FILL_VALUE);
		std::fill(zero_block.begin(), zero_block.end(), FILL_VALUE);
	}
	SetFilePointer(file, version_repository_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, zero_block.data(), zero_block.size(), &bytes_written, nullptr);
	SetFilePointer(file, version_repository_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, repository.c_str(), repository.size(), &bytes_written, nullptr);

	SetFilePointer(file, version_package_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, acpackage.c_str(), acpackage.size(), &bytes_written, nullptr);
}

static void set_launcher_strings(const HANDLE file, const std::pair<std::string, std::string> repository_information)
{
	const std::size_t repository_ptr = 0xD410; // URL
	const std::size_t repo_install_ptr = 0xD4A0; // URL file
	unsigned long bytes_written;

	SetFilePointer(file, repository_ptr, nullptr, FILE_BEGIN);
	WriteFile(file, repository_information.first.c_str(), repository_information.first.size(), &bytes_written, nullptr);
	SetFilePointer(file, repo_install_ptr, nullptr, FILE_BEGIN);
	WriteFile(file, repository_information.second.c_str(), repository_information.second.size(), &bytes_written, nullptr);

}

int main(void)
{
	std::ios::sync_with_stdio(false);
	std::string file_name;
	std::string repository;
	std::string package = "s_rvpackage.dll";

	std::cout << "Input working directory file: ";
	std::cin >> file_name;

	std::cout << "Input the online repository: ";
	std::cin >> repository;

	HANDLE file = CreateFileA(file_name.c_str(), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (file)
	{
		std::cout << "Working file opened. \n";
		if (check_version(file, ms_file_options::version_62))
		{
			set_file_string(file, ms_file_options::version_62, repository, package);
			set_file_obfuscation(ms_file_options::version_62, file);
		}
		else if (check_version(file, ms_file_options::version_83))
		{
			set_file_string(file, ms_file_options::version_83, repository, package);
			set_file_obfuscation(ms_file_options::version_62, file);
		}
		set_file_magic(file);
	}

	close_valid_handle(file);

	std::cout << "Input launcher path: ";
	std::cin >> file_name;

	std::cout << "Input the launcher installation repository: ";
	std::cin >> repository;

	std::cout << "Input launcher default installation file: ";
	std::cin >> package;

	file = CreateFileA(file_name.c_str(), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (file)
	{
		std::cout << "Launcher file opened. \n";
		set_launcher_strings(file, std::make_pair(repository, package));
		std::cout << "Status code: " << GetLastError() << std::endl;
	}

	close_valid_handle(file);

	std::cout << "Press any key to continue...\n";
	getchar();
	getchar();
    	return 0;
}

