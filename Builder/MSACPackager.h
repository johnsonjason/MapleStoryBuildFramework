#ifndef MSAC_PACKAGER
#define MSAC_PACKAGER

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
// <offset, size>
const std::vector<std::pair<std::size_t, std::size_t>> pair_ptr_set =
{
	{ 0x274F56, 0x50 }
};

const std::vector<std::pair<std::size_t, std::size_t>> pair_ptr_set83 =
{
	{ 0x397BFF, 0x50 }
};

// Map each version to a repository string
// version enum = <repository url input>
const std::unordered_map<ms_file_options, std::size_t> version_repository_map =
{
	{ ms_file_options::version_62, 0x6B0 },
	{ ms_file_options::version_83, 0x6B0 }
};

// Map each version to a digital file signature
// version enum = version signature/code to check for
const std::unordered_map<ms_file_options, std::pair<std::size_t, std::uint8_t>> version_signature_map =
{
	{ ms_file_options::version_62,{ 0x20EA30, 0xE8 } },
	{ ms_file_options::version_83,{ 0x20EA30, 0xE1 } }
};

// Map each version to a shellcode pairing
// version enum = <address<code>>
const std::unordered_map<ms_file_options, std::pair<std::size_t, std::vector<std::uint8_t>>> version_code_map =
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
	{ ms_file_options::version_83,
		{ 0x22EE54,
			{
				0x68, 0xA0, 0x06, 0x40, 0x00,
				0xFF, 0x15, 0xC0, 0x00, 0xAF, 0x00,
				0xE9, 0x8F, 0x51, 0x43, 0x00
			}
		}
	}
};

// Map each version to an entry point
// version enum = entry point
const std::unordered_map<ms_file_options, std::uint32_t> version_ep_map =
{
	{ ms_file_options::version_62, 0x0046EC24 },
	{ ms_file_options::version_83, 0x0022EE54 }
};

const std::unordered_map<ms_file_options, std::size_t> version_package_map =
{
	{ ms_file_options::version_62, 0x6A0 },
	{ ms_file_options::version_83, 0x690 }
};

const std::vector<std::uint8_t> enc_wsablock = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

const std::unordered_map<std::string, std::pair<std::size_t, std::vector<std::uint8_t>>> version_rt_encblocks =
{
	{ "v62wsa",{ 0x00274F50, enc_wsablock } }
};

const std::unordered_map<std::string, std::pair<std::size_t, std::vector<std::uint8_t>>> version_rt2_encblocks =
{
	{ "v83wsa",{ 0x00397BF9, enc_wsablock } }
};


void close_valid_handle(const HANDLE file);

std::uint8_t check_encoding(ms_file_options version, std::uint8_t flag);

std::vector<std::uint8_t>& encode_block(std::vector<std::uint8_t>& data_stream);
void write_file_point(const HANDLE file, const std::size_t file_start, const std::vector<std::uint8_t>& data_stream);

void get_file_data(const HANDLE file, std::vector<std::uint8_t>& data_stream,
	const std::pair<const std::size_t, const std::size_t>& ptr_set);

void set_file_obfuscation(ms_file_options version, const HANDLE file);
bool check_version(const HANDLE file, const ms_file_options version);
void set_ep(const ms_file_options version, void* data_map);

void set_shellcode(const ms_file_options version, std::vector<std::string>& keys, std::size_t data_map);
ms_file_options set_file_magic(const HANDLE file);

void set_file_string(const HANDLE file, const ms_file_options version, const std::string& repository, const std::string& acpackage);
void set_launcher_strings(const HANDLE file, const std::pair<std::string, std::string> repository_information);

#endif
