/*
* ���α׷��� ����
* 1. �ش� ���α׷��� PE����� Ž���Ͽ� RVA���� ���ϱ�
* 2. GET_PROCESS_NAME�� ���� �������� ac_client.exe�� PID ���� ���ϱ�
* 3. OpenProcess�� ���� ���μ����� �ڵ� ���� ���´�. * 4. ReadProcessMemory �Լ��� ���� ���α׷��� �޸� �ּҰ��� ��´�
* 5. ReadProcessMemory�� ���� �޸� �ּҰ��� RVA���� ���� �޸� ������ �õ��Ѵ�.
*/
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

// L : long | P : pointer | W : �����ڵ尡 ���ǵǾ��ٸ� LPWSTR�̰� �ƴ϶�� LPSTR�� �ȴ� | STR : string | C : constant
DWORD GET_PROCESS_NAME(LPWSTR name);
int RVA_Calc();

int main() {
	DWORD Find_Process_PID;
	DWORD Find_Process_Handle;
	int test = 0;

	Find_Process_PID = GET_PROCESS_NAME(L"ac_client.exe");
	Find_Process_Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Find_Process_PID);
	test = RVA_Calc();

	// OpenProcess�� ���� ���ٸ� ����
	if (Find_Process_Handle == NULL) {
		printf("Handle���� �����ϴ�.\n");
		return -1;
	}

	printf("e_magic: 0x%x\n", test);
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
		// PROCESSENTRY32 ����� �ʱ�ȭ�� ���� ������ ������ ���´�. Process_name.dwSize = sizeof(Process_name);
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
	}
	// snapshot ��ȯ ����
	else
		printf("NO snapshot\n");
}
int RVA_Calc() {
	IMAGE_DOS_HEADER dosHeader;
	FILE* Choice_File = NULL;

	fopen_s(&Choice_File, "C:\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\ac_client.exe", "rb");
	if (Choice_File == NULL) {
		printf("���� ���� ����\n");
		return 1;
	}

	fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, Choice_File);
	fclose(Choice_File);

	return dosHeader.e_magic;
}