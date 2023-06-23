#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <stdint.h>

// L : long | P : pointer | W : �����ڵ尡 ���ǵǾ��ٸ� LPWSTR�̰� �ƴ϶�� LPSTR�� �ȴ� | STR : string | C : constant
DWORD GET_PROCESS_NAME(LPWSTR name);
uint32_t RVA_Calc();

int main() {
	DWORD Find_Process_PID;
	DWORD Find_Process_Handle;
	uint32_t ReadMemory = NULL;
	ULONGLONG BaseAddress = 0;

	Find_Process_PID = GET_PROCESS_NAME(L"Notepad.exe");
	Find_Process_Handle = OpenProcess(PROCESS_VM_READ, FALSE, Find_Process_PID);
	BaseAddress = RVA_Calc();
	// OpenProcess�� ���� ���ٸ� ����
	if (Find_Process_Handle == NULL) {
		printf("Handle���� �����ϴ�.\n");
		return -1;
	}

	printf("BaseAddress = %u\n", BaseAddress);
	//ReadMemory = ReadProcessMemory(Find_Process_Handle, BaseAddress, );
	
	printf("Find_Process_PID : %d\n", Find_Process_PID);
	printf("Find_Process_Handle : %d\n", Find_Process_Handle);

	return 0;
}

// ���ϴ� ���μ����� PID���� �������� ��
DWORD GET_PROCESS_NAME(LPWSTR name) {
	// WORD = unsinged short, DWORD = unsinged long
	HANDLE snapshot = NULL;
	DWORD Process_pid = 0;
	PROCESSENTRY32 Process_name;
	/*
		�������� ���� �� �ý��� �ּ� ������ �ִ� ���μ��� ����� �׸��� ����
		dwSize : ����ü ũ��
		cntUsage : �̻��
		th32ProcessID : ���μ��� �ĺ�
		th32DefaultHeapID : �̻��
		th32ModuleID : �̻��
		cntThreads : ���μ������� ������ ���� ������ ��
		th32ParentProcessID : �ش� ���μ����� �θ� ���μ���
		pcPriClassBase : �� ���μ������� ���� �������� �⺻ �켱����
		dwFlags : �̻��
		szExeFile[MAX_PATH] : ���μ����� ���� ���� ���� �̸�
	*/

	// �������� ��� ���μ����� ����
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// snapshot ��ȯ ����
	if (snapshot != INVALID_HANDLE_VALUE) {
		// PROCESSENTRY32 ����� �ʱ�ȭ�� ���� ������ ������ ���´�. 
		Process_name.dwSize = sizeof(Process_name);
		if (Process32FirstW(snapshot, &Process_name)) {
			do {
				if (!wcscmp(Process_name.szExeFile, name)) {
					/* wcscmp ��� ���� : strcmp�� ASCII ���� ������ �������� ��* �ϴ� �ǵ�
					* Process_name.dwSize�� �ڷ����� wchar_t�̴�. * �߰� : wchar_t�� Ȯ�� ���� ���� ǥ������ �����ڵ� ���� ������ ��* ��
					* char�� ASCII ���� ������ ��� */
					Process_pid = Process_name.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &Process_name));
		}
		else if (Process_pid == 0) {
			// ���ϴ� ���μ����� ã�� ������ ���� ���� ó��
			printf("���ϴ� ���μ����� ã�� ���߽��ϴ�.\n");
			return -1;
		}
		CloseHandle(snapshot);
		return Process_name.th32ProcessID;
	}
	// snapshot ��ȯ ����
	else
		printf("NO snapshot\n");
}

uint32_t RVA_Calc() {
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionHeader;
	FILE* Choice_File = NULL;
	LONG exeHeader = 0;

	fopen_s(&Choice_File, "C:\\Windows\\System32\\Notepad.exe", "rb");
	if (Choice_File == NULL) {
		printf("���� ���� ����\n");
		return 1;
	}

	fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, Choice_File);
	exeHeader = dosHeader.e_lfanew;

	fseek(&dosHeader, exeHeader, 0);
	fread(&optionHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, Choice_File);
	fclose(Choice_File);

	return optionHeader.ImageBase;
}