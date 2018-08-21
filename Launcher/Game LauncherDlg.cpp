
// Game LauncherDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Game Launcher.h"
#include "Game LauncherDlg.h"
#include "afxdialogex.h"
#include "LauncherCore.h"
#include <mmsystem.h>

#pragma comment(lib, "Winmm.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CGameLauncherDlg dialog


CGameLauncherDlg::CGameLauncherDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_GameLAUNCHER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGameLauncherDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGameLauncherDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON4, &CGameLauncherDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON6, &CGameLauncherDlg::OnBnClickedButton6)
	ON_BN_CLICKED(IDC_BUTTON7, &CGameLauncherDlg::OnBnClickedButton7)
END_MESSAGE_MAP()


// CGameLauncherDlg message handlers

BOOL CGameLauncherDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	PlaySound(L"launchermusic.wav", NULL, SND_LOOP | SND_ASYNC);
	CEdit* edit_dlg = reinterpret_cast<CEdit*>(GetDlgItem(IDC_EDIT2));

	HANDLE file = CreateFileA("cerror.txt", GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	std::vector<char> file_stream;
	std::size_t bytes_read;
	file_stream.resize(128);
	ReadFile(file, &file_stream[0], file_stream.size(), reinterpret_cast<unsigned long*>(&bytes_read), nullptr);

	std::string serror(file_stream.begin(), file_stream.end());
	std::wstring error(serror.begin(), serror.end());

	edit_dlg->SetWindowTextW(error.c_str());
	close_valid_handle(file);
	DeleteFileA("cerror.txt");
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CGameLauncherDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CGameLauncherDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void install_game(const std::string& install_file)
{
	std::pair<std::string, std::string> repository_info = get_filebasename(install_file);
	if (pullc_gcontent(repository_info.first, "setup.txt", repository_info.second) == S_OK)
	{
		MessageBoxA(NULL, "Installation succeeded completely", "Installer", MB_OK);
		return;
	}
	else
	{
		MessageBoxA(NULL, "Installation is incomplete", "Installer", MB_OK);
		return;
	}
}

void CGameLauncherDlg::OnBnClickedButton4() // Game Launcher
{
	STARTUPINFOA startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };
	std::string launchobject_locator = "Game.exe";

	// Get the repository URL for the game
	std::string dl_object_url = get_fileinformation(launchobject_locator.c_str()) + "/Game.exe";
	std::string dl_object_path = "lverify.exe";

	// Get the anti-cheat repository
	std::string ac_object_url = "https://gitlab.com/....../";
	std::string ac_object_path = "s_rvpackage.dll";

	// Pull the game from the repository for verification
	if (pullc_gexec(dl_object_path, dl_object_url) != S_OK)
	{
		MessageBoxA(0, "The game launcher failed to load the executable(s)", "Error", MB_OK);
		return;
	}
	// Pull the anti-cheat from the repository
	if (pullc_gexec(ac_object_path, ac_object_url) != S_OK)
	{
		MessageBoxA(0, "The game launcher failed to load the executable(s)", "Error", MB_OK);
		return;
	}

	// Load the game in a suspended state for verification and deobfuscation
	if (load_game(launchobject_locator, startup_info, process_info) != INVALID_HANDLE_VALUE)
	{
		// Configure the game to be runnable by verifying the checksum and deobfuscating core components
		switch (configure_loadedgame(process_info, launchobject_locator, dl_object_path))
		{
		case 0:
			return;
		case 1:
			MessageBoxA(0, "File constraints detected.", "Error", MB_OK);
			break;
		case 2:
			MessageBoxA(0, "File corruption.", "Error", MB_OK);
			break;
		}
	}

	// Failure: cleanup and try to fix for the next run
	close_valid_handle(process_info.hThread);
	close_valid_handle(process_info.hProcess);

	DeleteFileA(launchobject_locator.c_str());
	MoveFileA(dl_object_path.c_str(), launchobject_locator.c_str());

	MessageBoxA(0, "Error loading game. ( Note: This requires administrative privileges to run. )", "Error", MB_OK);
	return;
}


void CGameLauncherDlg::OnBnClickedButton6() // Open Website
{
	ShellExecuteA(0, "open", "https://website.com/", 0, 0, SW_SHOWNORMAL);
}

void CGameLauncherDlg::OnBnClickedButton7() // Real About /Install
{
	install_game("config.txt");
}
