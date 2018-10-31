#include "stdafx.h"
#include "MSACPackager.h"

static volatile std::uint8_t encoding_status = 0;

void close_valid_handle(const HANDLE file)
{
	if (file != INVALID_HANDLE_VALUE && file != NULL)
	{
		CloseHandle(file);
	}
}

std::uint8_t check_encoding(ms_file_options version, std::uint8_t flag)
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

std::vector<std::uint8_t>& encode_block(std::vector<std::uint8_t>& data_stream)
{
	for (std::uint8_t& byte : data_stream)
	{
		byte = ((~byte) + 3);
	}
	return data_stream;
}

void write_file_point(const HANDLE file, const std::size_t file_start, const std::vector<std::uint8_t>& data_stream)
{
	unsigned long bytes_written;
	SetFilePointer(file, file_start, nullptr, FILE_BEGIN);
	WriteFile(file, data_stream.data(), data_stream.size(), &bytes_written, nullptr);
}

void get_file_data(const HANDLE file, std::vector<std::uint8_t>& data_stream,
	const std::pair<const std::size_t, const std::size_t>& ptr_set)
{
	unsigned long bytes_read;
	SetFilePointer(file, ptr_set.first, nullptr, FILE_BEGIN);
	ReadFile(file, &data_stream[0], data_stream.size(), &bytes_read, nullptr);
}

void set_file_obfuscation(ms_file_options version, const HANDLE file)
{
	std::vector<std::pair<std::size_t, std::size_t>> _pair_ptr_set;

	if (version == ms_file_options::version_62)
	{
		_pair_ptr_set = pair_ptr_set;
	}
	else if (version == ms_file_options::version_83)
	{
		_pair_ptr_set = pair_ptr_set83;
	}

	for (const std::pair<const std::size_t, const std::size_t>& ptr_set : _pair_ptr_set)
	{
		std::vector<std::uint8_t> data_stream;
		data_stream.resize(ptr_set.second);

		get_file_data(file, data_stream, ptr_set);
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

bool check_version(const HANDLE file, const ms_file_options version)
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

void set_ep(const ms_file_options version, void* data_map)
{
	PIMAGE_DOS_HEADER img_dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(data_map);
	PIMAGE_NT_HEADERS img_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(img_dos_headers) + img_dos_headers->e_lfanew);
	img_nt_headers->OptionalHeader.AddressOfEntryPoint = version_ep_map.at(version);
}

void set_shellcode(const ms_file_options version, std::vector<std::string>& keys, std::size_t data_map)
{
	void* _ptrseek = reinterpret_cast<void*>(data_map + version_code_map.at(version).first);
	std::vector<std::uint8_t> code = version_code_map.at(version).second;
	std::memcpy(_ptrseek, code.data(), code.size());

	try
	{
		if (version == ms_file_options::version_62)
		{
			for (std::string& key : keys)
			{
				std::pair<std::size_t, std::vector<std::uint8_t>> enc_block = version_rt_encblocks.at(key);
				_ptrseek = reinterpret_cast<void*>(data_map + enc_block.first);
				std::memcpy(_ptrseek, enc_block.second.data(), enc_block.second.size());
			}
		}
		else if (version == ms_file_options::version_83)
		{
			for (std::string& key : keys)
			{
				std::pair<std::size_t, std::vector<std::uint8_t>> enc_block = version_rt2_encblocks.at(key);
				_ptrseek = reinterpret_cast<void*>(data_map + enc_block.first);
				std::memcpy(_ptrseek, enc_block.second.data(), enc_block.second.size());
			}
		}
	}
	catch (std::out_of_range& e)
	{
		std::cout << "Map exception occurred." << std::endl;
	}
	return;
}

ms_file_options set_file_magic(const HANDLE file)
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

	if (check_version(file, ms_file_options::version_62))
	{
		std::vector<std::string> keys = { "v62wsa" };
		set_ep(ms_file_options::version_62, map_addr);
		set_shellcode(ms_file_options::version_62, keys, reinterpret_cast<std::size_t>(map_addr));

		UnmapViewOfFile(map_addr);
		close_valid_handle(map_object);

		return ms_file_options::version_62;
	}
	else if (check_version(file, ms_file_options::version_83))
	{
		std::vector<std::string> keys = { "v83wsa" };
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

void set_file_string(const HANDLE file, const ms_file_options version, const std::string& repository, const std::string& acpackage)
{
	unsigned long bytes_written;
	std::vector<unsigned char> zero_block;

	if (version == ms_file_options::version_62 || version == ms_file_options::version_83)
	{
		zero_block.resize(128);
		std::fill(zero_block.begin(), zero_block.end(), 0);
	}

	SetFilePointer(file, version_repository_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, zero_block.data(), zero_block.size(), &bytes_written, nullptr);
	SetFilePointer(file, version_repository_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, repository.c_str(), repository.size(), &bytes_written, nullptr);

	SetFilePointer(file, version_package_map.at(version), nullptr, FILE_BEGIN);
	WriteFile(file, acpackage.c_str(), acpackage.size(), &bytes_written, nullptr);
}

void set_launcher_strings(const HANDLE file, const std::pair<std::string, std::string> repository_information)
{
	const std::size_t repository_ptr = 0xD460; // URL
	const std::size_t repo_install_ptr = 0xD500; // URL file
	unsigned long bytes_written;

	SetFilePointer(file, repository_ptr, nullptr, FILE_BEGIN);
	WriteFile(file, repository_information.first.c_str(), repository_information.first.size(), &bytes_written, nullptr);
	SetFilePointer(file, repo_install_ptr, nullptr, FILE_BEGIN);
	WriteFile(file, repository_information.second.c_str(), repository_information.second.size(), &bytes_written, nullptr);

}
