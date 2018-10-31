#include "stdafx.h"
#include "LauncherCore.h"

ms_file_options client_version = ms_file_options::undefined;

void close_valid_handle(const HANDLE file)
{
	if (file != INVALID_HANDLE_VALUE && file != NULL)
	{
		CloseHandle(file);
	}
}

// <safe_getline> from stackoverflow <https://stackoverflow.com/questions/6089231/getting-std-ifstream-to-handle-lf-cr-and-crlf>
static std::ifstream& safe_getline(std::ifstream& is, std::string& t)
{
	t.clear();

	// The characters in the stream are read one-by-one using a std::streambuf.
	// That is faster than reading them one-by-one using the std::istream.
	// Code that uses streambuf this way must be guarded by a sentry object.
	// The sentry object performs various tasks,
	// such as thread synchronization and updating the stream state.

	std::ifstream::sentry se(is, true);
	std::streambuf* sb = is.rdbuf();

	for (;;) {
		int c = sb->sbumpc();
		switch (c) {
		case '\n':
			return is;
		case '\r':
			if (sb->sgetc() == '\n')
				sb->sbumpc();
			return is;
		case std::streambuf::traits_type::eof():
			// Also handle the case when the last line has no line ending
			if (t.empty())
				is.setstate(std::ios::eofbit);
			return is;
		default:
			t += (char)c;
		}
	}
}

std::size_t get_modbase(const std::uint32_t pid)
{
	HANDLE mod_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!mod_snap)
	{
		return 0;
	}

	MODULEENTRY32W mod_entry;
	mod_entry.dwSize = sizeof(MODULEENTRY32W);
	if (Module32FirstW(mod_snap, &mod_entry))
	{
		close_valid_handle(mod_snap);
		return reinterpret_cast<std::size_t>(mod_entry.modBaseAddr);
	}

	close_valid_handle(mod_snap);
	return 0;
}

void encode_block(std::vector<std::uint8_t>& data_stream)
{
	for (std::size_t data = 0; data < data_stream.size(); data++)
	{
		data_stream[data] = (~data_stream[data]) + 3;
	}
}


void decode_process(const HANDLE process, const std::size_t reference_base)
{
	std::vector<std::uint8_t> data_stream;
	std::vector<std::pair<std::size_t, std::size_t>> _virtual_ptrs;

	if (client_version == ms_file_options::version_62)
	{
		_virtual_ptrs = virtual_ptrs;
	}
	else if (client_version == ms_file_options::version_83)
	{
		_virtual_ptrs = virtual_ptrs83;
	}

	for (std::size_t crypt_ptr = 0; crypt_ptr < _virtual_ptrs.size(); crypt_ptr++)
	{
		unsigned long old_protect;
		void* virtual_ptr = reinterpret_cast<void*>(reference_base + _virtual_ptrs[crypt_ptr].first);

		data_stream.resize(_virtual_ptrs[crypt_ptr].second);

		ReadProcessMemory(process, virtual_ptr, &data_stream[0], _virtual_ptrs[crypt_ptr].second, nullptr);

		encode_block(data_stream);

		VirtualProtectEx(process, virtual_ptr, _virtual_ptrs[crypt_ptr].second, PAGE_EXECUTE_READWRITE, &old_protect);

		WriteProcessMemory(process, virtual_ptr, &data_stream[0], _virtual_ptrs[crypt_ptr].second, nullptr);

		VirtualProtectEx(process, virtual_ptr, _virtual_ptrs[crypt_ptr].second, old_protect, &old_protect);
	}
}

std::string get_filechecksum(std::string& file_name)
{
	std::vector<std::uint8_t> file_data;
	std::string file_hash;
	picosha2::hash256_one_by_one hash_stream;

	HANDLE checkfile = CreateFileA(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (checkfile == INVALID_HANDLE_VALUE)
	{
		return "";
	}

	hash_stream.init();

	std::vector<std::pair<std::size_t, std::size_t>> _file_ptrs;
	if (client_version == ms_file_options::version_62)
	{
		_file_ptrs = file_ptrs;
	}
	else if (client_version == ms_file_options::version_83)
	{
		_file_ptrs = file_ptrs83;
	}

	for (const std::pair<std::size_t, std::size_t>& ptr_set : _file_ptrs)
	{
		unsigned long bytes_read;

		file_data.resize(ptr_set.second);

		SetFilePointer(checkfile, ptr_set.first, nullptr, FILE_BEGIN);
		ReadFile(checkfile, &file_data[0], ptr_set.second, &bytes_read, nullptr);

		hash_stream.process(file_data.begin(), file_data.end());
	}

	hash_stream.finish();
	picosha2::get_hash_hex_string(hash_stream, file_hash);

	close_valid_handle(checkfile);
	return file_hash;
}

std::string get_processchecksum(std::uint32_t process_id, std::size_t reference_base)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, process_id);

	if (process == INVALID_HANDLE_VALUE)
	{
		return "";
	}

	std::vector<std::uint8_t> process_data;

	std::string process_hash;
	std::size_t module_base = reference_base;
	picosha2::hash256_one_by_one hash_stream;

	hash_stream.init();

	for (const std::pair<std::size_t, std::size_t>& ptr_set : virtual_ptrs)
	{
		std::size_t first = (module_base + ptr_set.first);

		process_data.resize(ptr_set.second);

		ReadProcessMemory(process, reinterpret_cast<void*>(first),
			&process_data[0], ptr_set.second, nullptr);

		hash_stream.process(process_data.begin(), process_data.end());
	}

	hash_stream.finish();
	picosha2::get_hash_hex_string(hash_stream, process_hash);

	close_valid_handle(process);
	return process_hash;
}

std::string get_fileinformation(const std::string& game)
{
	HANDLE gamefile = CreateFileA(game.c_str(), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (gamefile)
	{
		unsigned long bytes_read;
		std::vector<char> data_stream;
		data_stream.resize(260);

		SetFilePointer(gamefile, file_repository.at(client_version), nullptr, FILE_BEGIN);
		ReadFile(gamefile, &data_stream[0], data_stream.size(), &bytes_read, nullptr);
		close_valid_handle(gamefile);

		data_stream.erase(std::remove(data_stream.begin(), data_stream.end(), '\0'),  data_stream.end());
		data_stream.shrink_to_fit();

		return std::string(data_stream.begin(), data_stream.end());
	}
	return "";
}

// Launcher information
std::pair<std::string, std::string> get_filebasename(const std::string& config)
{
	unsigned long bytes_read;
	const std::size_t repository_ptr = 0xD460; // URL
	const std::size_t repo_install_ptr = 0xD500; // URL file
	std::vector<char> data_stream;
	std::pair<std::string, std::string> repository;

	HANDLE launcherfile = CreateFileA(config.c_str(), GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	data_stream.resize(128);

	SetFilePointer(launcherfile, repository_ptr, nullptr, FILE_BEGIN);
	ReadFile(launcherfile, &data_stream[0], data_stream.size(), &bytes_read, nullptr);
	data_stream.erase(std::remove(data_stream.begin(), data_stream.end(), '\0'), data_stream.end());

	repository.first = std::string(data_stream.begin(), data_stream.end());

	SetFilePointer(launcherfile, repo_install_ptr, nullptr, FILE_BEGIN);
	ReadFile(launcherfile, &data_stream[0], data_stream.size(), &bytes_read, nullptr);
	data_stream.erase(std::remove(data_stream.begin(), data_stream.end(), '\0'), data_stream.end());

	repository.second = std::string(data_stream.begin(), data_stream.end());

	return repository;
}

// C:\[CONFIG] => Download(config[1]) => PULL(repo/config[1]/setup) => get game
std::int32_t pullc_gcontent(const std::string& base_locator, const std::string& base_target, const std::string& url_gc_locator)
{
	std::string full_url = base_locator + "/" + base_target;
	DeleteFileA(full_url.c_str());
	std::int32_t dl_status = URLDownloadToFileA(NULL, full_url.c_str(), url_gc_locator.c_str(), 0, NULL);
	if (dl_status != S_OK)
	{
		return dl_status;
	}

	std::ifstream dl_file(base_target.c_str());
	std::string download_req;
	if (dl_file.is_open())
	{
		while (safe_getline(dl_file, download_req))
		{
			if (download_req.empty())
			{
				break;
			} 

			std::size_t name_pos = download_req.find_last_of("-");
			std::string file_name;

			if (name_pos == std::string::npos)
			{
				file_name = download_req.substr(name_pos + 1, std::string::npos);
			}
			else
			{
				file_name = download_req.substr(name_pos + 2, std::string::npos);
			}

			std::string file_url = download_req.substr(0, name_pos - 1);
			DeleteFileA(file_name.c_str());
			dl_status = URLDownloadToFileA(NULL, file_url.c_str(), file_name.c_str(), 0, NULL);
		}

		dl_file.close();
	}
	return dl_status;
}

std::int32_t pullc_gexec(const std::string& url_game_locator, const std::string& game_url)
{
	DeleteFileA(url_game_locator.c_str());
	std::int32_t dl_status = URLDownloadToFileA(NULL, game_url.c_str(), url_game_locator.c_str(), 0, NULL);
	return dl_status;
}

HANDLE load_game(const std::string& game, STARTUPINFOA& startup_info, PROCESS_INFORMATION& process_info)
{
	CreateProcessA(game.c_str(), NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info);
	return process_info.hProcess;
}

std::uint8_t configure_loadedgame(const PROCESS_INFORMATION& process_info, std::string& launcher, std::string& check_launcher)
{
	std::string fchecksum = get_filechecksum(launcher);
	std::string ufchecksum = get_filechecksum(check_launcher);
	std::string pchecksum = get_processchecksum(process_info.dwProcessId, 0);

	if (fchecksum.size() == 0 || ufchecksum.size() == 0 || pchecksum.size() == 0)
	{
		close_valid_handle(process_info.hThread);
		close_valid_handle(process_info.hProcess);
		DeleteFileA(check_launcher.c_str());
		return 1;
	}
	else if (fchecksum == ufchecksum && fchecksum == pchecksum)
	{
		decode_process(process_info.hProcess, 0);
		ResumeThread(process_info.hThread);
		close_valid_handle(process_info.hProcess);
		close_valid_handle(process_info.hThread);

		DeleteFileA(check_launcher.c_str());
		TerminateProcess(GetCurrentProcess(), 0);
		return 0;
	}
	return 2;
}

void set_version(const ms_file_options version)
{
	client_version = version;
}
