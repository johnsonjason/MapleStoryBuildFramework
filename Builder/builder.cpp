// Patches the game executable for the launcher to work with it

#include "stdafx.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <unordered_map>

#define FILL_VALUE 0

enum class ms_file_options : std::size_t
{
	undefined,
	version_62,
	version_83
};

// Obfuscation/encoding offsets
static const std::vector<std::pair<const std::size_t, const std::size_t>> pair_ptr_set =
{
	{ 0x1000, 0x1000 },
	{ 0x2004, 0x1000 }
};

// Map each version to a repository string
// version enum = <repository url input>
static const std::unordered_map<const ms_file_options, std::size_t> version_repository_map =
{
	{ ms_file_options::version_62, 0x573AF8},
	{ ms_file_options::version_83, FILL_VALUE}
};

// Map each version to a digital file signature
// version enum = version signature/code to check for
static const std::unordered_map<const ms_file_options, const std::pair<const std::size_t, const std::uint8_t>> version_signature_map =
{
	{ ms_file_options::version_62, { 0x20EA30, 0xE8 } },
	{ ms_file_options::version_83, { FILL_VALUE, FILL_VALUE } }
};

// Map each version to a shellcode pairing
// version enum = <address<code>>
static const std::unordered_map<const ms_file_options, std::pair<std::size_t, std::vector<std::uint8_t>>> version_code_map =
{
	{ ms_file_options::version_62, { FILL_VALUE, { FILL_VALUE } } },
	{ ms_file_options::version_83, { FILL_VALUE, { FILL_VALUE } } }
};

// Map each version to an entry point
// version enum = entry point
static const std::unordered_map<const ms_file_options, const std::uint32_t> version_ep_map =
{
	{ ms_file_options::version_62, 0x0056EC24 },
	{ ms_file_options::version_83, FILL_VALUE }
};

static void close_valid_handle(const HANDLE file)
{
	if (file != INVALID_HANDLE_VALUE && file != NULL)
	{
		CloseHandle(file);
	}
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

static void set_file_obfuscation(const HANDLE file)
{
	for (const std::pair<const std::size_t, const std::size_t>& ptr_set : pair_ptr_set)
	{
		std::vector<std::uint8_t> data_stream;
		data_stream.resize(ptr_set.second);

		get_file_data(file, data_stream, ptr_set);
		write_file_point(file, ptr_set.first, encode_block(data_stream));
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

static void set_shellcode(const ms_file_options version, void* data_map)
{
	void* _ptrseek = reinterpret_cast<void*>(version_code_map.at(version).first);
	std::vector<std::uint8_t> code = version_code_map.at(version).second;
	std::memcpy(_ptrseek, code.data(), code.size());
	return;
}

static ms_file_options set_file_magic(const HANDLE file)
{
	HANDLE map_object = CreateFileMappingW(file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	void* map_addr = MapViewOfFileEx(map_object, FILE_MAP_ALL_ACCESS, 0, 0, 0, nullptr);

	if (check_version(file, ms_file_options::version_62))
	{
		set_ep(ms_file_options::version_62, map_addr);
		set_shellcode(ms_file_options::version_62, map_addr);

		UnmapViewOfFile(map_addr);
		close_valid_handle(map_object);

		return ms_file_options::version_62;
	}
	else if (check_version(file, ms_file_options::version_83))
	{
		set_ep(ms_file_options::version_83, map_addr);
		set_shellcode(ms_file_options::version_83, map_addr);

		UnmapViewOfFile(map_addr);
		close_valid_handle(map_object);

		return ms_file_options::version_83;
	}

	UnmapViewOfFile(map_addr);
	close_valid_handle(map_object);
	return ms_file_options::undefined;
}

static void set_file_string(const HANDLE file, const ms_file_options version, const std::string& repository)
{
	unsigned long bytes_written;
	std::vector<unsigned char> zero_block;
	if (version == ms_file_options::version_62)
	{
		zero_block.resize(768);
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
}

int main(void)
{
	std::ios::sync_with_stdio(false);
	std::string file_name;
	std::string repository;

	std::cout << "Input working directory file: ";
	std::cin >> file_name;

	HANDLE file = CreateFileA(file_name.c_str(), GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	std::cout << "Input the online repository: ";
	std::cin >> repository;

	if (file)
	{
		if (check_version(file, ms_file_options::version_62))
		{
			set_file_string(file, ms_file_options::version_62, repository);
		}
		else if (check_version(file, ms_file_options::version_83))
		{
			set_file_string(file, ms_file_options::version_83, repository);
		}
		set_file_obfuscation(file);
		set_file_magic(file);
	}

	close_valid_handle(file);
    return 0;
}

