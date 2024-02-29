#include <Windows.h>
#include <stdio.h>
#include <CONIO.h>

#pragma warning(disable:4996)

//�������½ṹ������һ�� InlineHook ����Ҫ����Ϣ
typedef struct _HOOK_DATA
{
	char szApiName[128];             // ��Hook��API������
	char szModuleName[64];           // ��Hook��API����ģ�������
	int HookCodeLen;                 // Hook����
	BYTE oldEntry[16];               // ����Hookλ�õ�ԭʼָ��
	BYTE newEntry[16];               // ����Ҫд��Hookλ�õ���ָ��
	ULONG_PTR HookPoint;             // ��HOOK��λ��
	ULONG_PTR JmpBackAddr;           // ������ԭ������λ��
	ULONG_PTR pfnTrampolineFun;      // ����ԭʼ������ͨ��
	ULONG_PTR pfnDetourFun;          // Hook ���˺���

}HOOK_DATA, * PHOOK_DATA;

#define HOOKLEN (5)         // Ҫ��д��ָ��ĳ���
HOOK_DATA MsgBoxHookData;

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);
LPVOID GetAddress(char*, char*);
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
BOOL Inline_InstallHook(void);
BOOL Inline_UnInstallHook();
BOOL InstallCodeHook(PHOOK_DATA pHookData);
BOOL UninstallCodeHook(PHOOK_DATA pHookData);

int main()
{
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	Inline_InstallHook();
	MessageBoxA(NULL, "After Inline Hook", "Test", MB_OK);
	Inline_UnInstallHook();
	MessageBoxA(NULL, "After  Inline Hook Unhooked", "Test", MB_OK);
	return 0;
}

//************************************
// Method:    FakeMessageBox
// FullName:  FakeMessageBox
// Purpose:   ȡ��ԭʼMessageBoxA�Ĺ���,HOOK�����ж�MessageBoxA�ĵ��ý�ʵ�ʵ��ñ�����
// Author:    achillis
// Returns:   int WINAPI
// Parameter: HWND hWnd
// Parameter: LPCTSTR lpText
// Parameter: LPCTSTR lpCaption
// Parameter: UINT uType
//************************************
//ע�⺯���Ķ����ԭʼ����һ��Ҫһ���������ǵ���Լ�������������غ󽫳���
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	//���������Զ�ԭʼ���������������
	int ret;
	char newText[1024] = { 0 };
	char newCaption[256] = "pediy.com";
	printf("���˵���MessageBox!\n");
	//�ڵ���ԭ����֮ǰ�����Զ�IN(������)�������и���
	lstrcpy(newText, lpText);//Ϊ��ֹԭ�����ṩ�Ļ��������������︴�Ƶ������Լ���һ�����������ٽ��в���
	lstrcat(newText, "\n\tMessageBox Hacked by pediy.com!");//�۸���Ϣ������
	uType |= MB_ICONERROR;//����һ������ͼ��
	ret = OriginalMessageBox(hWnd, newText, newCaption, uType);//����ԭMessageBox�������淵��ֵ
	//����ԭ����֮�󣬿��Լ�����OUT(�����)�������и���,�������纯����recv�����Ը��淵�ص�����
	return ret;//�����㻹���Ը���ԭʼ�����ķ���ֵ
}


BOOL Inline_InstallHook(void)
{
	// ׼��Hook,�������ݶ�����׼�� HOOK_DATA �ṹ������
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));        // Ҫ Hook ��Ŀ��ģ�鼰Ŀ�꺯��
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookCodeLen = 5;                        // Hook ָ��ĳ���
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);        // �� Hook �ĵ�ַ
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;               // ����ԭʼ���庯����ͨ��
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;                       // Fake

	return InstallCodeHook(&MsgBoxHookData);
}

BOOL Inline_UnInstallHook()
{
	return UninstallCodeHook(&MsgBoxHookData);
}

/*
MessageBoxA �Ĵ��뿪ͷ
77D5050B >  8BFF                   mov edi,edi
77D5050D    55                     push ebp
77D5050E    8BEC                   mov ebp,esp
77D50510    833D 1C04D777 00       cmp dword ptr ds:[gfEMIEnable],0
*/
// ����Ҫ����ԭʼ�� MessageBox ʱ��ֱ�ӵ��ô˺������ɣ�������ȫ��ͬ
__declspec(naked)
int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	_asm
	{
		// ��������д��� Jmp ָ���ƻ���ԭ����ǰ 3 ��ָ����������ִ��ԭ������ǰ 3 ��ָ��
		mov edi, edi      // ��һ����Բ�Ҫ
		push ebp
		mov ebp, esp
		jmp MsgBoxHookData.JmpBackAddr      // ����Hook����֮��ĵط����ƹ��Լ���װ��Hook
	}

}

//��ȡָ��ģ����ָ��API�ĵ�ַ
LPVOID GetAddress(char* dllname, char* funname)
{
	HMODULE hMod = 0;
	if (hMod = GetModuleHandle(dllname))         // ����֤hMod��Ϊ��
	{
		return GetProcAddress(hMod, funname);
	}
	else
	{
		hMod = LoadLibrary(dllname);
		return GetProcAddress(hMod, funname);
	}

}

/*
   �������һ��Ҫ����ָ��
   ʹ�õ��� 5 �ֽڵ�Jmp
*/
void InitHookEntry(PHOOK_DATA pHookData)
{
	if (pHookData == NULL
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->HookPoint == NULL)
	{
		return;
	}

	pHookData->newEntry[0] = 0xE9;      // Jmp��JMP 16λ������ֵ
	// ������תƫ�Ʋ�д��
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;//0xE9 ʽjmp�ļ���
}


ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
	ULONG_PTR TrueAddress = 0;
	PBYTE pFn = (PBYTE)uAddress;

	if (memcmp(pFn, "\xFF\x25", 2) == 0)      // ����ʹ�� memcmp ����������ַ��Ӧ��ǰ�����ֽڣ��������Ƿ�Ϊ "\xFF\x25"�������ͬ�Ļ�����ʾ�õ�ַ����ָ������תָ����ź�����ӵ�ַ�ж�ȡ�洢����ת��ַ�������丳ֵ�� TrueAddress�������ַͨ����һ�������תָ���ζ�Ż���ת���洢��ָ���ڴ��ַ��Ŀ���ַ��
	{
		TrueAddress = *(ULONG_PTR*)(pFn + 2);
		return TrueAddress;
	}
	if (pFn[0] == 0xE9)      // Long Jmp �Ļ����룬JMP 16λ������ֵ,       SkipJmpAddress(pHookData->pfnTrampolineFun);
	{
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;          // �������תָ��ƫ�Ƽ� 5 ���ֽ�
		return TrueAddress;
	}
	if (pFn[0] == 0xEB)      // JMP 8λ������ֵ
	{
		TrueAddress = (ULONG_PTR)pFn + pFn[1] + 2;         // �������תָ��ƫ�Ƽ� 2 ���ֽ�
		return TrueAddress;
	}
	printf("pFn[0] = 0x%x\n", pFn[0]);

	return (ULONG_PTR)uAddress;
}

// ע�� HOOK_DATA ���ݵ������У�����Hook����
BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
	DWORD dwBytesReturned = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;

	if (pHookData == NULL
		|| pHookData->HookPoint == 0
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}

	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);    // �ߵڶ�����֧
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);                 // û�����κη�֧��ֱ�ӷ���,���ص�pFn[0]=0x8B,movָ��
	// ���������ͷ����ת����ô��������
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;

	InitHookEntry(pHookData);         // ��� Inline Hook ����
	//if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned)) , ���ﵼ�´�������ˣ���oldEntry
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))
	{
		if (WriteProcessMemory(hProcess,         // Ҫ�޸ĵĽ����ڴ���
			OriginalAddr,                        // ָ��д�����ݵ�ָ�������еĻ���ַ��ָ��
			pHookData->newEntry,                 // ָ�򻺳�����ָ��
			pHookData->HookCodeLen,              // Ҫд��ָ�����̵��ֽ���
			&dwBytesReturned))                   // ָ�������ָ��
		{
			printf("Install Hook write OK! WrittenCnt = %d\n", dwBytesReturned);
			bResult = TRUE;
		}
	}
	return bResult;
}

BOOL UninstallCodeHook(PHOOK_DATA HookData)
{
	SIZE_T* dwBytesReturned = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;
	LPVOID OriginalAddr;
	if (HookData == NULL
		|| HookData->HookPoint == 0
		|| HookData->oldEntry[0] == 0)
	{
		return FALSE;
	}

	OriginalAddr = (LPVOID)HookData->HookPoint;
	bResult = WriteProcessMemory(hProcess, OriginalAddr, HookData->oldEntry, HookData->HookCodeLen, dwBytesReturned);
	return bResult;
}





