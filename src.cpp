BOOL InjectDll
(
	DWORD dwPID,
	LPCTSTR szDllPath
)
{
	HANDLE                  hProcess, hThread;
	LPVOID                  pRemoteBuf;
	DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc;


	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}


BOOL EjectDll
(
	DWORD dwPID,
	LPCTSTR szDllPath
)
{
	BOOL                    bMore = FALSE, bFound = FALSE;
	HANDLE                  hSnapshot, hProcess, hThread;
	MODULEENTRY32           me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (INVALID_HANDLE_VALUE ==
		(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID))) {
		return FALSE;
	}

	bMore = Module32First(hSnapshot, &me);

	do {
		if ((_tcsicmp(me.szModule,  szDllPath) == NO_ERROR) ||
			(_tcsicmp(me.szExePath, szDllPath) == NO_ERROR)) {
			bFound = TRUE;
			break;
		}
	} while (bMore = Module32Next(hSnapshot, &me));

	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}


BOOL InjectTargetProcess
(
  LPCTSTR szTargetPath,
  LPCTSTR szDllPath,
  BOOL bInject
)
{
	HANDLE         hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry32;
	BOOL           bResult = FALSE;


	entry32.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return bResult;
	}

	BOOL bRet = Process32First(hSnapshot, &entry32);

	do {
		if (_tcsicmp(entry32.szExeFile, szTargetPath) == 0) {
			if (bInject) {
				InjectDll(entry32.th32ProcessID, szDllPath);
			} else {
				EjectDll(entry32.th32ProcessID, szDllPath);
			}
			break;
		}
	} while (bRet = Process32Next(hSnapshot, &entry32));

	CloseHandle(hSnapshot);
	return bResult;
}
