/************************************************************************
 *   IRC - Internet Relay Chat, win32/gui.c
 *   Copyright (C) 2000-2004 David Flynn (DrBin) & Dominick Meglio (codemastr)
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef UDB
#define WIN32_VERSION BASE_VERSION PATCH1 PATCH2 PATCH3 PATCH4 PATCH5 PATCH6
#else
#define WIN32_VERSION BASE_VERSION PATCH1 PATCH2 PATCH3 PATCH4
#endif
#include "resource.h"
#include "version.h"
#include "setup.h"
#ifdef INET6
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <io.h>
#include <direct.h>
#include <errno.h>
#include "h.h"
#include <richedit.h>
#include <commdlg.h>
#include "win32.h"

__inline void ShowDialog(HWND *handle, HINSTANCE inst, char *template, HWND parent, 
			 DLGPROC proc)
{
	if (!IsWindow(*handle)) 
	{
		*handle = CreateDialog(inst, template, parent, (DLGPROC)proc); 
		ShowWindow(*handle, SW_SHOW);
	}
	else
		SetForegroundWindow(*handle);
}

/* Comments:
 * 
 * DrBin did a great job with the original GUI, but he has been gone a long time.
 * In his absense, it was decided it would be best to continue windows development.
 * The new code is based on his so it will be pretty much similar in features, my
 * main goal is to make it more stable. A lot of what I know about GUI coding 
 * I learned from DrBin so thanks to him for teaching me :) -- codemastr
 */

LRESULT CALLBACK MainDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK LicenseDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK CreditsDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK DalDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK HelpDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK StatusDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK ConfigErrorDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK FromVarDLG(HWND, UINT, WPARAM, LPARAM, unsigned char *, unsigned char **);
LRESULT CALLBACK FromFileReadDLG(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK FromFileDLG(HWND, UINT, WPARAM, LPARAM);

extern  void      SocketLoop(void *dummy);
HINSTANCE hInst;
NOTIFYICONDATA SysTray;
void CleanUp(void);
HTREEITEM AddItemToTree(HWND, LPSTR, int, short);
void win_map(aClient *, HWND, short);
extern Link *Servers;
extern ircstats IRCstats;
unsigned char *errors = NULL;
extern aMotd *botmotd, *opermotd, *motd, *rules;
extern VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
extern BOOL IsService;
void CleanUp(void)
{
	Shell_NotifyIcon(NIM_DELETE ,&SysTray);
}
void CleanUpSegv(int sig)
{
	Shell_NotifyIcon(NIM_DELETE ,&SysTray);
}
HWND hStatusWnd;
HWND hwIRCDWnd=NULL;
HWND hwTreeView;
HWND hWndMod;
HANDLE hMainThread = 0;
UINT WM_TASKBARCREATED, WM_FINDMSGSTRING;
FARPROC lpfnOldWndProc;
HMENU hContext;
OSVERSIONINFO VerInfo;
char OSName[256];
#ifdef USE_LIBCURL
extern char *find_loaded_remote_include(char *url);
#endif 

void TaskBarCreated() 
{
	HICON hIcon = (HICON)LoadImage(hInst, MAKEINTRESOURCE(ICO_MAIN), IMAGE_ICON,16, 16, 0);
	SysTray.cbSize = sizeof(NOTIFYICONDATA);
	SysTray.hIcon = hIcon;
	SysTray.hWnd = hwIRCDWnd;
	SysTray.uCallbackMessage = WM_USER;
	SysTray.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE;
	SysTray.uID = 0;
	strcpy(SysTray.szTip, WIN32_VERSION);
	Shell_NotifyIcon(NIM_ADD ,&SysTray);
}

LRESULT LinkSubClassFunc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	static HCURSOR hCursor;
	if (!hCursor)
		hCursor = LoadCursor(hInst, MAKEINTRESOURCE(CUR_HAND));
	if (Message == WM_MOUSEMOVE || Message == WM_LBUTTONDOWN)
		SetCursor(hCursor);

	return CallWindowProc((WNDPROC)lpfnOldWndProc, hWnd, Message, wParam, lParam);
}



LRESULT RESubClassFunc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	POINT p;
	RECT r;
	DWORD start, end;
	unsigned char string[500];

	if (Message == WM_GETDLGCODE)
	   return DLGC_WANTALLKEYS;

	
	if (Message == WM_CONTEXTMENU) 
	{
		p.x = GET_X_LPARAM(lParam);
		p.y = GET_Y_LPARAM(lParam);
		if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1) 
		{
			GetClientRect(hWnd, &r);
			p.x = (int)((r.left + r.right)/2);
			p.y = (int)((r.top + r.bottom)/2);
			ClientToScreen(hWnd,&p);
		}
		if (!SendMessage(hWnd, EM_CANUNDO, 0, 0)) 
			EnableMenuItem(hContext, IDM_UNDO, MF_BYCOMMAND|MF_GRAYED);
		else
			EnableMenuItem(hContext, IDM_UNDO, MF_BYCOMMAND|MF_ENABLED);
		if (!SendMessage(hWnd, EM_CANPASTE, 0, 0)) 
			EnableMenuItem(hContext, IDM_PASTE, MF_BYCOMMAND|MF_GRAYED);
		else
			EnableMenuItem(hContext, IDM_PASTE, MF_BYCOMMAND|MF_ENABLED);
		if (GetWindowLong(hWnd, GWL_STYLE) & ES_READONLY) 
		{
			EnableMenuItem(hContext, IDM_CUT, MF_BYCOMMAND|MF_GRAYED);
			EnableMenuItem(hContext, IDM_DELETE, MF_BYCOMMAND|MF_GRAYED);
		}
		else 
		{
			EnableMenuItem(hContext, IDM_CUT, MF_BYCOMMAND|MF_ENABLED);
			EnableMenuItem(hContext, IDM_DELETE, MF_BYCOMMAND|MF_ENABLED);
		}
		SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
		if (start == end) 
			EnableMenuItem(hContext, IDM_COPY, MF_BYCOMMAND|MF_GRAYED);
		else
			EnableMenuItem(hContext, IDM_COPY, MF_BYCOMMAND|MF_ENABLED);
		TrackPopupMenu(hContext,TPM_LEFTALIGN|TPM_RIGHTBUTTON,p.x,p.y,0,GetParent(hWnd),NULL);
		return 0;
	}

	return CallWindowProc((WNDPROC)lpfnOldWndProc, hWnd, Message, wParam, lParam);
}

int CloseUnreal(HWND hWnd)
{
	if (MessageBox(hWnd, "�Quieres cerrar UnrealIRCd?", "�Est�s seguro?", MB_YESNO|MB_ICONQUESTION) == IDNO)
		 return 0;
	else 
	{
		 DestroyWindow(hWnd);
		 exit(0);
	}
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	MSG msg;
	unsigned char *s;
	HWND hWnd;
	WSADATA WSAData;
	HICON hIcon;
	SERVICE_TABLE_ENTRY DispatchTable[] = 
	{
		{ "UnrealIRCd", ServiceMain },
		{ 0, 0 }
	};
	DWORD need;
	
	VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&VerInfo);
	GetOSName(VerInfo, OSName);
	if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT) 
	{
		SC_HANDLE hService, hSCManager = OpenSCManager(NULL, NULL, GENERIC_EXECUTE);
		if ((hService = OpenService(hSCManager, "UnrealIRCd", GENERIC_EXECUTE))) 
		{
			int save_err = 0;
			StartServiceCtrlDispatcher(DispatchTable); 
			if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			{ 
				SERVICE_STATUS status;
				/* Restart handling, it's ugly but it's as 
				 * pretty as it is gonna get :)
				 */
				if (__argc == 2 && !strcmp(__argv[1], "restartsvc"))
				{
					QueryServiceStatus(hService, &status);
					if (status.dwCurrentState != SERVICE_STOPPED)
					{
						ControlService(hService,
							SERVICE_CONTROL_STOP, &status);
						while (status.dwCurrentState == SERVICE_STOP_PENDING)
						{
							QueryServiceStatus(hService, &status);
							if (status.dwCurrentState != SERVICE_STOPPED)
								Sleep(1000);
						}
					}
				}
				if (!StartService(hService, 0, NULL))
					save_err = GetLastError();
			}

			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			if (save_err != ERROR_SERVICE_DISABLED)
				exit(0);
		} else {
			CloseServiceHandle(hSCManager);
		}
	}
	InitCommonControls();
	WM_TASKBARCREATED = RegisterWindowMessage("TaskbarCreated");
	WM_FINDMSGSTRING = RegisterWindowMessage(FINDMSGSTRING);
	atexit(CleanUp);
	if(!LoadLibrary("riched20.dll"))
		LoadLibrary("riched32.dll");
	InitDebug();

	if (WSAStartup(MAKEWORD(1, 1), &WSAData) != 0)
    	{
		MessageBox(NULL, "No se puede iniciar WinSock", "UnrealIRCD Error Inicio", MB_OK);
		return FALSE;
	}
	hInst = hInstance; 
    
	hWnd = CreateDialog(hInstance, "WIRCD", 0, (DLGPROC)MainDLG); 
	hwIRCDWnd = hWnd;
	
	TaskBarCreated();

	if (InitwIRCD(__argc, __argv) != 1)
	{
		MessageBox(NULL, "No se puede iniciar UnrealIRCd en InitwIRCD()", "UnrealIRCD Error Inicio" ,MB_OK);
		return FALSE;
	}
	ShowWindow(hWnd, SW_SHOW);
	hMainThread = (HANDLE)_beginthread(SocketLoop, 0, NULL);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!IsWindow(hStatusWnd) || !IsDialogMessage(hStatusWnd, &msg)) 
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	return FALSE;

}

LRESULT CALLBACK MainDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HCURSOR hCursor;
	static HMENU hRehash, hAbout, hConfig, hTray, hLogs;

	unsigned char *argv[3];
	aClient *paClient;
	unsigned char *msg;
	POINT p;

	if (message == WM_TASKBARCREATED)
	{
		TaskBarCreated();
		return TRUE;
	}
	
	switch (message)
	{
		case WM_INITDIALOG: 
		{
			ShowWindow(hDlg, SW_HIDE);
			hCursor = LoadCursor(hInst, MAKEINTRESOURCE(CUR_HAND));
			hContext = GetSubMenu(LoadMenu(hInst, MAKEINTRESOURCE(MENU_CONTEXT)),0);
			/* Rehash popup menu */
			hRehash = GetSubMenu(LoadMenu(hInst, MAKEINTRESOURCE(MENU_REHASH)),0);
			/* About popup menu */
			hAbout = GetSubMenu(LoadMenu(hInst, MAKEINTRESOURCE(MENU_ABOUT)),0);
			/* Systray popup menu set the items to point to the other menus*/
			hTray = GetSubMenu(LoadMenu(hInst, MAKEINTRESOURCE(MENU_SYSTRAY)),0);
			ModifyMenu(hTray, IDM_REHASH, MF_BYCOMMAND|MF_POPUP|MF_STRING, (UINT)hRehash, "&Rehash");
			ModifyMenu(hTray, IDM_ABOUT, MF_BYCOMMAND|MF_POPUP|MF_STRING, (UINT)hAbout, "&About");
			
			SetWindowText(hDlg, WIN32_VERSION);
			SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_SMALL, 
				(LPARAM)(HICON)LoadImage(hInst, MAKEINTRESOURCE(ICO_MAIN), IMAGE_ICON,16, 16, 0));
			SendMessage(hDlg, WM_SETICON, (WPARAM)ICON_BIG, 
				(LPARAM)(HICON)LoadImage(hInst, MAKEINTRESOURCE(ICO_MAIN), IMAGE_ICON,32, 32, 0));
			return TRUE;
		}
		case WM_SIZE: 
		{
			if (wParam & SIZE_MINIMIZED)
				ShowWindow(hDlg,SW_HIDE);
			return 0;
		}
		case WM_CLOSE: 
			return CloseUnreal(hDlg);
		case WM_USER: 
		{
			switch(LOWORD(lParam)) 
			{
				case WM_LBUTTONDBLCLK:
					ShowWindow(hDlg, SW_SHOW);
					ShowWindow(hDlg,SW_RESTORE);
					SetForegroundWindow(hDlg);
				case WM_RBUTTONDOWN:
					SetForegroundWindow(hDlg);
					break;
				case WM_RBUTTONUP: 
				{
					unsigned long i = 60000;
					MENUITEMINFO mii;
					GetCursorPos(&p);
					DestroyMenu(hConfig);
					hConfig = CreatePopupMenu();
					DestroyMenu(hLogs);
					hLogs = CreatePopupMenu();
					AppendMenu(hConfig, MF_STRING, IDM_CONF, CPATH);
					if (conf_log) 
					{
						ConfigItem_log *logs;
						AppendMenu(hConfig, MF_POPUP|MF_STRING, (UINT)hLogs, "Logs");
						for (logs = conf_log; logs; logs = (ConfigItem_log *)logs->next) 
						{
							AppendMenu(hLogs, MF_STRING, i++, logs->file);
						}
					}
					AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
					if (conf_include) 
					{
						ConfigItem_include *inc;
						for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next) 
						{
							if (inc->flag.type & INCLUDE_NOTLOADED)
								continue;
#ifdef USE_LIBCURL
							if (inc->flag.type & INCLUDE_REMOTE)
								AppendMenu(hConfig, MF_STRING, i++, inc->url);
							else
#endif
							AppendMenu(hConfig, MF_STRING, i++, inc->file);
						}
						AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
					}
					AppendMenu(hConfig, MF_STRING, IDM_MOTD, MPATH);
					AppendMenu(hConfig, MF_STRING, IDM_SMOTD, SMPATH);
					AppendMenu(hConfig, MF_STRING, IDM_OPERMOTD, OPATH);
					AppendMenu(hConfig, MF_STRING, IDM_BOTMOTD, BPATH);
					AppendMenu(hConfig, MF_STRING, IDM_RULES, RPATH);
						
					if (conf_tld) 
					{
						ConfigItem_tld *tlds;
						AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
						for (tlds = conf_tld; tlds; tlds = (ConfigItem_tld *)tlds->next) 
						{
							if (!tlds->flag.motdptr)
								AppendMenu(hConfig, MF_STRING, i++, tlds->motd_file);
							if (!tlds->flag.rulesptr)
								AppendMenu(hConfig, MF_STRING, i++, tlds->rules_file);
							if (tlds->smotd_file)
								AppendMenu(hConfig, MF_STRING, i++, tlds->smotd_file);
						}
					}
					AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
					AppendMenu(hConfig, MF_STRING, IDM_NEW, "New File");
					mii.cbSize = sizeof(MENUITEMINFO);
					mii.fMask = MIIM_SUBMENU;
					mii.hSubMenu = hConfig;
					SetMenuItemInfo(hTray, IDM_CONFIG, MF_BYCOMMAND, &mii);
					TrackPopupMenu(hTray, TPM_LEFTALIGN|TPM_LEFTBUTTON,p.x,p.y,0,hDlg,NULL);
					/* Kludge for a win bug */
					SendMessage(hDlg, WM_NULL, 0, 0);
					break;
				}
			}
			return 0;
		}
		case WM_DESTROY:
			return 0;
		case WM_MOUSEMOVE: 
		{
			POINT p;
			p.x = LOWORD(lParam);
			p.y = HIWORD(lParam);
			if ((p.x >= 24) && (p.x <= 78) && (p.y >= 178) && (p.y <= 190)) 
				SetCursor(hCursor);
			else if ((p.x >= 85) && (p.x <= 132) && (p.y >= 178) && (p.y <= 190)) 
				SetCursor(hCursor);
			else if ((p.x >= 140) && (p.x <= 186) && (p.y >= 178) && (p.y <= 190)) 
				SetCursor(hCursor);
			else if ((p.x >= 194) && (p.x <= 237) && (p.y >= 178) && (p.y <= 190)) 
				SetCursor(hCursor);
			else if ((p.x >= 245) && (p.x <= 311) && (p.y >= 178) && (p.y <= 190)) 
				SetCursor(hCursor);
			return 0;
		}
		case WM_LBUTTONDOWN: 
		{
			POINT p;
	         	p.x = LOWORD(lParam);
		     	p.y = HIWORD(lParam);
			if ((p.x >= 24) && (p.x <= 78) && (p.y >= 178) && (p.y <= 190))
             		{
				ClientToScreen(hDlg,&p);
				TrackPopupMenu(hRehash,TPM_LEFTALIGN|TPM_LEFTBUTTON,p.x,p.y,0,hDlg,NULL);
				return 0;
			}
			else if ((p.x >= 85) && (p.x <= 132) && (p.y >= 178) && (p.y <= 190))
			{
				ShowDialog(&hStatusWnd, hInst, "Status", hDlg, StatusDLG);
				return 0;
			}
			else if ((p.x >= 140) && (p.x <= 186) && (p.y >= 178) && (p.y <= 190))
			{
				unsigned long i = 60000;
				ClientToScreen(hDlg,&p);
				DestroyMenu(hConfig);
				hConfig = CreatePopupMenu();
				DestroyMenu(hLogs);
				hLogs = CreatePopupMenu();

				AppendMenu(hConfig, MF_STRING, IDM_CONF, CPATH);
				if (conf_log) 
				{
					ConfigItem_log *logs;
					AppendMenu(hConfig, MF_POPUP|MF_STRING, (UINT)hLogs, "Logs");
					for (logs = conf_log; logs; logs = (ConfigItem_log *)logs->next) 
					{
						AppendMenu(hLogs, MF_STRING, i++, logs->file);
					}
				}
				AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);

				if (conf_include) 
				{
					ConfigItem_include *inc;
					for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next) 
					{
#ifdef USE_LIBCURL
						if (inc->flag.type & INCLUDE_REMOTE)
							AppendMenu(hConfig, MF_STRING, i++, inc->url);
						else
#endif
						AppendMenu(hConfig, MF_STRING, i++, inc->file);
					}
					AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
				}

				AppendMenu(hConfig, MF_STRING, IDM_MOTD, MPATH);
				AppendMenu(hConfig, MF_STRING, IDM_SMOTD, SMPATH);
				AppendMenu(hConfig, MF_STRING, IDM_OPERMOTD, OPATH);
				AppendMenu(hConfig, MF_STRING, IDM_BOTMOTD, BPATH);
				AppendMenu(hConfig, MF_STRING, IDM_RULES, RPATH);
				
				if (conf_tld) 
				{
					ConfigItem_tld *tlds;
					AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
					for (tlds = conf_tld; tlds; tlds = (ConfigItem_tld *)tlds->next) 
					{
						if (!tlds->flag.motdptr)
							AppendMenu(hConfig, MF_STRING, i++, tlds->motd_file);
						if (!tlds->flag.rulesptr)
							AppendMenu(hConfig, MF_STRING, i++, tlds->rules_file);
						if (tlds->smotd_file)
							AppendMenu(hConfig, MF_STRING, i++, tlds->smotd_file);
					}
				}
				AppendMenu(hConfig, MF_SEPARATOR, 0, NULL);
				AppendMenu(hConfig, MF_STRING, IDM_NEW, "Nuevo");
				TrackPopupMenu(hConfig,TPM_LEFTALIGN|TPM_LEFTBUTTON,p.x,p.y,0,hDlg,NULL);

				return 0;
			}
			else if ((p.x >= 194) && (p.x <= 237) && (p.y >= 178) && (p.y <= 190)) 
			{
				ClientToScreen(hDlg,&p);
				TrackPopupMenu(hAbout,TPM_LEFTALIGN|TPM_LEFTBUTTON,p.x,p.y,0,hDlg,NULL);
				return 0;
			}
			else if ((p.x >= 245) && (p.x <= 311) && (p.y >= 178) && (p.y <= 190)) 
				return CloseUnreal(hDlg);
		}
		case WM_COMMAND: 
		{
			if (LOWORD(wParam) >= 60000 && HIWORD(wParam) == 0 && !lParam) 
			{
				unsigned char path[MAX_PATH];
				if (GetMenuString(hLogs, LOWORD(wParam), path, MAX_PATH, MF_BYCOMMAND))
					DialogBoxParam(hInst, "FromVar", hDlg, (DLGPROC)FromFileReadDLG, (LPARAM)path);
				
				else 
				{
					GetMenuString(hConfig,LOWORD(wParam), path, MAX_PATH, MF_BYCOMMAND);
#ifdef USE_LIBCURL
					if (url_is_valid(path))
					{
						char *file = find_loaded_remote_include(path);
						DialogBoxParam(hInst, "FromVar", hDlg, (DLGPROC)FromFileReadDLG, (LPARAM)file);
					}
					else
#endif
						DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG, (LPARAM)path);
				}
				return FALSE;
			}

			switch(LOWORD(wParam)) 
			{
				case IDM_STATUS:
					ShowDialog(&hStatusWnd, hInst, "Status", hDlg,StatusDLG);
					break;
				case IDM_SHUTDOWN:
					return CloseUnreal(hDlg);
				case IDM_RHALL:
					MessageBox(NULL, "Refrescando todos los archivos", "Refrescando", MB_OK);
					sendto_realops("Refrescando todos los archivos v�a consola");
					rehash(&me,&me,0);
					reread_motdsandrules();
					break;
				case IDM_RHCONF:
					MessageBox(NULL, "Refrescando archivo de configuraci�n", "Refrescando", MB_OK);
					sendto_realops("Refrescando archivo de configuraci�n v�a consola");
					rehash(&me,&me,0);
					break;
				case IDM_RHMOTD: 
				{
					ConfigItem_tld *tlds;
					aMotd *amotd;
					MessageBox(NULL, "Refrescando todos los MOTD y archivos RULES", "Refrescando", MB_OK);
					rehash_motdrules();
					sendto_realops("Refrescando todos los MOTD y archivos RULES v�a consola");
					break;
				}
				case IDM_RHOMOTD:
					MessageBox(NULL, "Refrescando OPERMOTD", "Refrescando", MB_OK);
					opermotd = (aMotd *) read_file(OPATH, &opermotd);
					sendto_realops("Refrescando OPERMOTD v�a consola");
					break;
				case IDM_RHBMOTD:
					MessageBox(NULL, "Refrescando BotMOTD", "Refrescando", MB_OK);
					botmotd = (aMotd *) read_file(BPATH, &botmotd);
					sendto_realops("Refrescando BotMOTD v�a consola");
					break;
				case IDM_LICENSE: 
					DialogBox(hInst, "FromVar", hDlg, (DLGPROC)LicenseDLG);
					break;
				case IDM_CREDITS:
					DialogBox(hInst, "FromVar", hDlg, (DLGPROC)CreditsDLG);
					break;
				case IDM_DAL:
					DialogBox(hInst, "FromVar", hDlg, (DLGPROC)DalDLG);
					break;
				case IDM_HELP:
					DialogBox(hInst, "Help", hDlg, (DLGPROC)HelpDLG);
					break;
				case IDM_CONF:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG, 
						(LPARAM)CPATH);
					break;
				case IDM_MOTD:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG, 
						(LPARAM)MPATH);
					break;
				case IDM_SMOTD:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG, 
						(LPARAM)SMPATH);
					break;
				case IDM_OPERMOTD:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG,
						(LPARAM)OPATH);
					break;
				case IDM_BOTMOTD:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG,
						(LPARAM)BPATH);
					break;
				case IDM_RULES:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG,
						(LPARAM)RPATH);
					break;
				case IDM_NEW:
					DialogBoxParam(hInst, "FromFile", hDlg, (DLGPROC)FromFileDLG, (LPARAM)NULL);
					break;
			}
		}
	}
	return FALSE;
}

LRESULT CALLBACK LicenseDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	return FromVarDLG(hDlg, message, wParam, lParam, "Licencia UnrealIRCd", gnulicense);
}

LRESULT CALLBACK CreditsDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	return FromVarDLG(hDlg, message, wParam, lParam, "Cr�ditos UnrealIRCd", unrealcredits);
}

LRESULT CALLBACK DalDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	return FromVarDLG(hDlg, message, wParam, lParam, "DALnet Cr�ditos UnrealIRCd", dalinfotext);
}

LRESULT CALLBACK FromVarDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam,
			    unsigned char *title, unsigned char **s) 
{
	HWND hWnd;
	switch (message) 
	{
		case WM_INITDIALOG: 
		{
			unsigned char	String[16384];
			int size;
			unsigned char *RTFString;
			StreamIO *stream = malloc(sizeof(StreamIO));
			EDITSTREAM edit;
			SetWindowText(hDlg, title);
			bzero(String, 16384);
			lpfnOldWndProc = (FARPROC)SetWindowLong(GetDlgItem(hDlg, IDC_TEXT), GWL_WNDPROC, (DWORD)RESubClassFunc);
			while (*s) 
			{
				strcat(String, *s++);
				if (*s)
					strcat(String, "\r\n");
			}
			size = CountRTFSize(String)+1;
			RTFString = malloc(size);
			bzero(RTFString, size);
			IRCToRTF(String,RTFString);
			RTFBuf = RTFString;
			size--;
			stream->size = &size;
			stream->buffer = &RTFBuf;
			edit.dwCookie = (UINT)stream;
			edit.pfnCallback = SplitIt;
			SendMessage(GetDlgItem(hDlg, IDC_TEXT), EM_STREAMIN, (WPARAM)SF_RTF|SFF_PLAINRTF, (LPARAM)&edit);
			free(RTFString);	
			free(stream);
			return TRUE;
		}

		case WM_COMMAND: 
		{
			hWnd = GetDlgItem(hDlg, IDC_TEXT);
			if (LOWORD(wParam) == IDOK)
				return EndDialog(hDlg, TRUE);
			if (LOWORD(wParam) == IDM_COPY) 
			{
				SendMessage(hWnd, WM_COPY, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_SELECTALL) 
			{
				SendMessage(hWnd, EM_SETSEL, 0, -1);
				return 0;
			}
			if (LOWORD(wParam) == IDM_PASTE) 
			{
				SendMessage(hWnd, WM_PASTE, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_CUT) 
			{
				SendMessage(hWnd, WM_CUT, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_UNDO) 
			{
				SendMessage(hWnd, EM_UNDO, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_DELETE) 
			{
				SendMessage(hWnd, WM_CLEAR, 0, 0);
				return 0;
			}
			break;
		}
		case WM_CLOSE:
			EndDialog(hDlg, TRUE);
			break;
		case WM_DESTROY:
			break;
		}
	return (FALSE);
}

LRESULT CALLBACK FromFileReadDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	HWND hWnd;
	switch (message) 
	{
		case WM_INITDIALOG: 
		{
			int fd,len;
			unsigned char *buffer = '\0', *string = '\0';
			EDITSTREAM edit;
			StreamIO *stream = malloc(sizeof(StreamIO));
			unsigned char szText[256];
			struct stat sb;
			HWND hWnd = GetDlgItem(hDlg, IDC_TEXT), hTip;
			wsprintf(szText, "UnrealIRCd Visor - %s", (unsigned char *)lParam);
			SetWindowText(hDlg, szText);
			lpfnOldWndProc = (FARPROC)SetWindowLong(hWnd, GWL_WNDPROC, (DWORD)RESubClassFunc);
			if ((fd = open((unsigned char *)lParam, _O_RDONLY|_O_BINARY)) != -1) 
			{
				fstat(fd,&sb);
				/* Only allocate the amount we need */
				buffer = malloc(sb.st_size+1);
				buffer[0] = 0;
				len = read(fd, buffer, sb.st_size); 
				buffer[len] = 0;
				len = CountRTFSize(buffer)+1;
				string = malloc(len);
				bzero(string,len);
				IRCToRTF(buffer,string);
				RTFBuf = string;
				len--;
				stream->size = &len;
				stream->buffer = &RTFBuf;
				edit.dwCookie = (UINT)stream;
				edit.pfnCallback = SplitIt;
				SendMessage(hWnd, EM_EXLIMITTEXT, 0, (LPARAM)0x7FFFFFFF);
				SendMessage(hWnd, EM_STREAMIN, (WPARAM)SF_RTF|SFF_PLAINRTF, (LPARAM)&edit);
				close(fd);
				RTFBuf = NULL;
				free(buffer);
				free(string);
				free(stream);
			}
			return TRUE;
		}
		case WM_COMMAND: 
		{
			hWnd = GetDlgItem(hDlg, IDC_TEXT);
			if (LOWORD(wParam) == IDOK)
				return EndDialog(hDlg, TRUE);
			if (LOWORD(wParam) == IDM_COPY) 
			{
				SendMessage(hWnd, WM_COPY, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_SELECTALL) 
			{
				SendMessage(hWnd, EM_SETSEL, 0, -1);
				return 0;
			}
			if (LOWORD(wParam) == IDM_PASTE) 
			{
				SendMessage(hWnd, WM_PASTE, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_CUT) 
			{
				SendMessage(hWnd, WM_CUT, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_UNDO) 
			{
				SendMessage(hWnd, EM_UNDO, 0, 0);
				return 0;
			}
			if (LOWORD(wParam) == IDM_DELETE) 
			{
				SendMessage(hWnd, WM_CLEAR, 0, 0);
				return 0;
			}
			break;
		}
		case WM_CLOSE:
			EndDialog(hDlg, TRUE);
			break;
		case WM_DESTROY:
			break;
	}
	return FALSE;
}

LRESULT CALLBACK HelpDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	static HFONT hFont;
	static HCURSOR hCursor;
	switch (message) 
	{
		case WM_INITDIALOG:
			hCursor = LoadCursor(hInst, MAKEINTRESOURCE(CUR_HAND));
			hFont = CreateFont(8,0,0,0,0,0,1,0,ANSI_CHARSET,0,0,PROOF_QUALITY,0,"MS Sans Serif");
			SendMessage(GetDlgItem(hDlg, IDC_EMAIL), WM_SETFONT, (WPARAM)hFont,TRUE);
			SendMessage(GetDlgItem(hDlg, IDC_URL), WM_SETFONT, (WPARAM)hFont,TRUE);
			lpfnOldWndProc = (FARPROC)SetWindowLong(GetDlgItem(hDlg, IDC_EMAIL), GWL_WNDPROC, (DWORD)LinkSubClassFunc);
			SetWindowLong(GetDlgItem(hDlg, IDC_URL), GWL_WNDPROC, (DWORD)LinkSubClassFunc);
			return TRUE;

		case WM_DRAWITEM: 
		{
			LPDRAWITEMSTRUCT lpdis = (LPDRAWITEMSTRUCT)lParam;
			unsigned char text[500];
			COLORREF oldtext;
			RECT focus;
			GetWindowText(lpdis->hwndItem, text, 500);
			if (wParam == IDC_URL || IDC_EMAIL) 
			{
				FillRect(lpdis->hDC, &lpdis->rcItem, GetSysColorBrush(COLOR_3DFACE));
				oldtext = SetTextColor(lpdis->hDC, RGB(0,0,255));
				DrawText(lpdis->hDC, text, strlen(text), &lpdis->rcItem, DT_CENTER|DT_VCENTER);
				SetTextColor(lpdis->hDC, oldtext);
				if (lpdis->itemState & ODS_FOCUS) 
				{
					CopyRect(&focus, &lpdis->rcItem);
					focus.left += 2;
					focus.right -= 2;
					focus.top += 1;
					focus.bottom -= 1;
					DrawFocusRect(lpdis->hDC, &focus);
				}
				return TRUE;
			}
		}	
		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK)
				EndDialog(hDlg, TRUE);
			if (HIWORD(wParam) == BN_DBLCLK) 
			{
				if (LOWORD(wParam) == IDC_URL) 
					ShellExecute(NULL, "open", "http://www.unrealircd.com", NULL, NULL, 
						SW_MAXIMIZE);
				else if (LOWORD(wParam) == IDC_EMAIL)
					ShellExecute(NULL, "open", "mailto:unreal-users@lists.sourceforge.net", NULL, NULL, 
						SW_MAXIMIZE);
				EndDialog(hDlg, TRUE);
				return 0;
			}
			break;
		case WM_CLOSE:
			EndDialog(hDlg, TRUE);
			break;
		case WM_DESTROY:
			DeleteObject(hFont);
			break;

	}
	return FALSE;
}








LRESULT CALLBACK StatusDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	switch (message) 
	{
		case WM_INITDIALOG: 
		{
			hwTreeView = GetDlgItem(hDlg, IDC_TREE);
			win_map(&me, hwTreeView, 0);
			SetDlgItemInt(hDlg, IDC_CLIENTS, IRCstats.clients, FALSE);
			SetDlgItemInt(hDlg, IDC_SERVERS, IRCstats.servers, FALSE);
			SetDlgItemInt(hDlg, IDC_INVISO, IRCstats.invisible, FALSE);
			SetDlgItemInt(hDlg, IDC_UNKNOWN, IRCstats.unknown, FALSE);
			SetDlgItemInt(hDlg, IDC_OPERS, IRCstats.operators, FALSE);
			SetDlgItemInt(hDlg, IDC_CHANNELS, IRCstats.channels, FALSE);
			if (IRCstats.clients > IRCstats.global_max)
				IRCstats.global_max = IRCstats.clients;
			if (IRCstats.me_clients > IRCstats.me_max)
					IRCstats.me_max = IRCstats.me_clients;
			SetDlgItemInt(hDlg, IDC_MAXCLIENTS, IRCstats.global_max, FALSE);
			SetDlgItemInt(hDlg, IDC_LCLIENTS, IRCstats.me_clients, FALSE);
			SetDlgItemInt(hDlg, IDC_LSERVERS, IRCstats.me_servers, FALSE);
			SetDlgItemInt(hDlg, IDC_LMAXCLIENTS, IRCstats.me_max, FALSE);
			SetTimer(hDlg, 1, 5000, NULL);
			return TRUE;
		}
		case WM_CLOSE:
			DestroyWindow(hDlg);
			return TRUE;
		case WM_TIMER:
			TreeView_DeleteAllItems(hwTreeView);
			win_map(&me, hwTreeView, 1);
			SetDlgItemInt(hDlg, IDC_CLIENTS, IRCstats.clients, FALSE);
			SetDlgItemInt(hDlg, IDC_SERVERS, IRCstats.servers, FALSE);
			SetDlgItemInt(hDlg, IDC_INVISO, IRCstats.invisible, FALSE);
			SetDlgItemInt(hDlg, IDC_INVISO, IRCstats.invisible, FALSE);
			SetDlgItemInt(hDlg, IDC_UNKNOWN, IRCstats.unknown, FALSE);
			SetDlgItemInt(hDlg, IDC_OPERS, IRCstats.operators, FALSE);
			SetDlgItemInt(hDlg, IDC_CHANNELS, IRCstats.channels, FALSE);
			if (IRCstats.clients > IRCstats.global_max)
				IRCstats.global_max = IRCstats.clients;
			if (IRCstats.me_clients > IRCstats.me_max)
					IRCstats.me_max = IRCstats.me_clients;
			SetDlgItemInt(hDlg, IDC_MAXCLIENTS, IRCstats.global_max, FALSE);
			SetDlgItemInt(hDlg, IDC_LCLIENTS, IRCstats.me_clients, FALSE);
			SetDlgItemInt(hDlg, IDC_LSERVERS, IRCstats.me_servers, FALSE);
			SetDlgItemInt(hDlg, IDC_LMAXCLIENTS, IRCstats.me_max, FALSE);
			SetTimer(hDlg, 1, 5000, NULL);
			return TRUE;
		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK) 
			{
				DestroyWindow(hDlg);
				return TRUE;
			}
			break;

	}
	return FALSE;
}

/* This was made by DrBin but I cleaned it up a bunch to make it work better */

HTREEITEM AddItemToTree(HWND hWnd, LPSTR lpszItem, int nLevel, short remap)
{
	TVITEM tvi; 
	TVINSERTSTRUCT tvins; 
	static HTREEITEM hPrev = (HTREEITEM)TVI_FIRST; 
	static HTREEITEM hPrevLev[10] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	HTREEITEM hti; 

	if (remap) 
	{
		hPrev = (HTREEITEM)TVI_FIRST;
		memset(hPrevLev, 0, sizeof(HTREEITEM)*10);
	}
		
	tvi.mask = TVIF_TEXT|TVIF_PARAM; 
	tvi.pszText = lpszItem; 
	tvi.cchTextMax = lstrlen(lpszItem); 
	tvi.lParam = (LPARAM)nLevel; 
	tvins.item = tvi; 
	tvins.hInsertAfter = hPrev; 
	if (nLevel == 1) 
		tvins.hParent = TVI_ROOT; 
	else 
		tvins.hParent = hPrevLev[nLevel-1];
	hPrev = (HTREEITEM)SendMessage(hWnd, TVM_INSERTITEM, 0, (LPARAM)(LPTVINSERTSTRUCT) &tvins); 
	hPrevLev[nLevel] = hPrev;
	TreeView_EnsureVisible(hWnd,hPrev);
	if (nLevel > 1) 
	{ 
	        hti = TreeView_GetParent(hWnd, hPrev); 
        	tvi.mask = TVIF_IMAGE|TVIF_SELECTEDIMAGE; 
	        tvi.hItem = hti; 
	        TreeView_SetItem(hWnd, &tvi); 
	} 
	return hPrev; 
}

/*
 * Now used to create list of servers for server list tree view -- David Flynn
 * Recoded by codemastr to be faster.
 * I removed the Potvin credit because it no longer uses any original code and I don't
 * even think Potvin actually made the original code
 */
void win_map(aClient *server, HWND hwTreeView, short remap)
{
        aClient *acptr;
	Link *lp;

	AddItemToTree(hwTreeView,server->name,server->hopcount+1, remap);

	for (lp = Servers; lp; lp = lp->next)
        {
                acptr = lp->value.cptr;
                if (acptr->srvptr != server)
                        continue;
                win_map(acptr, hwTreeView, 0);
        }
}

/* ugly stuff, but hey it works -- codemastr */
void win_log(unsigned char *format, ...) 
{
        va_list ap;
        unsigned char buf[2048];
		unsigned char *buf2;
        va_start(ap, format);
        ircvsprintf(buf, format, ap);
	if (!IsService) 
	{
		strcat(buf, "\r\n");
		if (errors) 
		{
			buf2 = MyMalloc(strlen(errors)+strlen(buf)+1);
			sprintf(buf2, "%s%s",errors,buf);
			MyFree(errors);
			errors = NULL;
		}
		else 
		{
			buf2 = MyMalloc(strlen(buf)+1);
			sprintf(buf2, "%s",buf);
		}
		errors = buf2;
	}
	else 
	{
		FILE *fd = fopen("service.log", "a");
		if (fd)
		{
			fprintf(fd, "%s\n", buf);
			fclose(fd);
		}
#ifdef _DEBUG
		else
		{
		    OutputDebugString(buf);
		}
#endif
	}
        va_end(ap);
}

void win_error() 
{
	if (errors && !IsService)
		DialogBox(hInst, "ConfigError", hwIRCDWnd, (DLGPROC)ConfigErrorDLG);
}

LRESULT CALLBACK ConfigErrorDLG(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	switch (message) 
	{
		case WM_INITDIALOG:
			MessageBeep(MB_ICONEXCLAMATION);
			SetDlgItemText(hDlg, IDC_CONFIGERROR, errors);
			MyFree(errors);
			errors = NULL;
			return (TRUE);
		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK)
				EndDialog(hDlg, TRUE);
			break;
		case WM_CLOSE:
			EndDialog(hDlg, TRUE);
			break;
		case WM_DESTROY:
			break;

		}
	return (FALSE);
}
