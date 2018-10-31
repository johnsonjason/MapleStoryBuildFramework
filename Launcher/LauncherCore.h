#ifndef LAUNCHER_CORE
#define LAUNCHER_CORE
#include <Windows.h>
#include <TlHelp32.h>
#include "picosha2.h"
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <unordered_map>

enum class ms_file_options : std::size_t
{
	undefined,
	version_62,
	version_83
};

// <offset, size> encoding ptrs
const std::vector<std::pair<std::size_t, std::size_t>> file_ptrs =
{
	{ 0x274F56, 0x50 }
};

const std::vector<std::pair<std::size_t, std::size_t>> file_ptrs83 =
{
	{ 0x397BFF, 0x50 }
};

// <offset, size> encoding ptrs
const std::vector<std::pair<std::size_t, std::size_t>> virtual_ptrs =
{
	{ 0x00674F56, 0x50 }
};

const std::vector<std::pair<std::size_t, std::size_t>> virtual_ptrs83 =
{
	{ 0x00797BFF, 0x50 }
};

const std::unordered_map<ms_file_options, std::pair<std::size_t, std::uint8_t>> version_signature_map =
{
	{ ms_file_options::version_62, { 0x20EA30, 0xE8 } },
	{ ms_file_options::version_83, { 0x20EA30, 0xE1 } }
};

const std::unordered_map<ms_file_options, std::size_t> file_repository = 
{
	{ ms_file_options::version_62, 0x6B0 },
	{ ms_file_options::version_83, 0x6B0 }
};

extern ms_file_options client_version;

void close_valid_handle(const HANDLE file);
void set_version(const ms_file_options version);
void encode_block(std::vector<std::uint8_t>& data_stream);
void decode_process(const HANDLE process, const std::size_t reference_base);

std::string get_filechecksum(std::string& file_name);
std::string get_processchecksum(std::uint32_t process_id, std::size_t reference_base);
std::string get_fileinformation(const std::string& game);

std::pair<std::string, std::string> get_filebasename(const std::string& config);
std::size_t get_modbase(const std::uint32_t pid);

HANDLE load_game(const std::string& game, STARTUPINFOA& startup_info, PROCESS_INFORMATION& process_info);
std::uint8_t configure_loadedgame(const PROCESS_INFORMATION& process_info, std::string& launcher, std::string& check_launcher);
std::int32_t pullc_gcontent(const std::string& base_locator, const std::string& base_target, const std::string& url_gc_locator);
std::int32_t pullc_gexec(const std::string& url_game_locator, const std::string& game_url);

#endif
