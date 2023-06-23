#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

// L : long | P : pointer | W : 유니코드가 정의되었다면 LPWSTR이고 아니라면 LPSTR로 된다 | STR : string | C : constant
DWORD GET_PROCESS_NAME(LPWSTR name);
int RVA_Calc();

int main() {
	DWORD Find_Process_PID;
	DWORD Find_Process_Handle;
	int test = 0;

	Find_Process_PID = GET_PROCESS_NAME(L"Notepad.exe");
	Find_Process_Handle = OpenProcess(PROCESS_VM_READ, FALSE, Find_Process_PID);
	test = RVA_Calc();

	// OpenProcess에 값이 없다면 실행
	if (Find_Process_Handle == NULL) {
		printf("Handle값이 없습니다.\n");
		return -1;
	}

	printf("e_magic: 0x%x\n", test);
	printf("Find_Process_PID : %d\n", Find_Process_PID);
	printf("Find_Process_Handle : %d\n", Find_Process_Handle);

	return 0;
}

// 원하는 프로세스의 PID값을 가져오는 곳
DWORD GET_PROCESS_NAME(LPWSTR name) {
	// WORD = unsinged short, DWORD = unsinged long
	HANDLE snapshot = NULL;
	DWORD Process_pid = 0;
	PROCESSENTRY32 Process_name;
	/*
		스냅샷을 만들 때 시스템 주소 공간에 있는 프로세스 목록의 항목을 설명
		dwSize : 구조체 크기
		cntUsage : 미사용
		th32ProcessID : 프로세스 식별
		th32DefaultHeapID : 미사용
		th32ModuleID : 미사용
		cntThreads : 프로세스에서 시작한 실행 스레드 수
		th32ParentProcessID : 해당 프로세스의 부모 프로세스
		pcPriClassBase : 이 프로세스에서 만든 스레드의 기본 우선순이
		dwFlags : 미사용
		szExeFile[MAX_PATH] : 프로세스에 대한 실행 파일 이름
	*/

	// 스냅샷의 모든 프로세스를 포함
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// snapshot 반환 성공
	if (snapshot != INVALID_HANDLE_VALUE) {
		// PROCESSENTRY32 사이즈를 초기화를 하지 않으면 오류가 나온다. 
		Process_name.dwSize = sizeof(Process_name);
		if (Process32FirstW(snapshot, &Process_name)) {
			do {
				if (!wcscmp(Process_name.szExeFile, name)) {
					/* wcscmp 사용 이유 : strcmp는 ASCII 문자 집합을 기준으로 비교* 하는 건데
					* Process_name.dwSize의 자료형은 wchar_t이다. * 추가 : wchar_t는 확장 문자 집합 표현으로 유니코드 문자 집합을 사* 용
					* char는 ASCII 문자 집합을 사용 */
					Process_pid = Process_name.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &Process_name));
		}
		else if (Process_pid == 0) {
			// 원하는 프로세스를 찾지 못했을 때에 대한 처리
			printf("원하는 프로세스를 찾지 못했습니다.\n");
			return -1;
		}
		CloseHandle(snapshot);
		return Process_name.th32ProcessID;
	}
	// snapshot 반환 실패
	else
		printf("NO snapshot\n");
}
int RVA_Calc() {
	IMAGE_DOS_HEADER dosHeader;
	FILE* Choice_File = NULL;

	fopen_s(&Choice_File, "C:\\Windows\\System32\\Notepad.exe", "rb");
	if (Choice_File == NULL) {
		printf("파일 열기 실패\n");
		return 1;
	}

	fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, Choice_File);
	fclose(Choice_File);

	return dosHeader.e_magic;
}