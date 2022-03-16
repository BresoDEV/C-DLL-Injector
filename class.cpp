 
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
using namespace std;

int getProcId(const wchar_t* target)
{
	DWORD pID = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	do {
		if (wcscmp(pe32.szExeFile, target) == 0)
		{
			CloseHandle(hSnapshot);
			pID = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);
	return pID;
}

int main()
{
	const wchar_t* process = L"ac_client.exe";
	int pID = getProcId(process);
	if (pID > 0)
	{
		char dll[] = "mod.dll";
		char dllPatch[MAX_PATH] = { 0 };
		GetFullPathNameA(dll, MAX_PATH, dllPatch, NULL);

		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pID);
		LPVOID pszLibFileRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPatch) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		WriteProcessMemory(hProcess, pszLibFileRemote, dllPatch, strlen(dllPatch) + 1, NULL);
		HANDLE handleThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA,
			pszLibFileRemote, NULL, NULL);

		WaitForSingleObject(handleThread, INFINITE);
		CloseHandle(handleThread);
		VirtualFreeEx(hProcess, dllPatch, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		cout << "Dll injetada com sucesso!!! POOORAAAAAAAAAA" << endl;
		return 1;
	}
	else
	{
		return 0;
	}
	
	 
}
