#include <Windows.h>
#include <stdio.h>
#include <CONIO.h>

#pragma warning(disable:4996)

//定义如下结构，保存一次 InlineHook 所需要的信息
typedef struct _HOOK_DATA
{
	char szApiName[128];             // 待Hook的API的名字
	char szModuleName[64];           // 待Hook的API所属模块的名字
	int HookCodeLen;                 // Hook长度
	BYTE oldEntry[16];               // 保存Hook位置的原始指令
	BYTE newEntry[16];               // 保存要写入Hook位置的新指令
	ULONG_PTR HookPoint;             // 待HOOK的位置
	ULONG_PTR JmpBackAddr;           // 回跳到原函数的位置
	ULONG_PTR pfnTrampolineFun;      // 调用原始函数的通道
	ULONG_PTR pfnDetourFun;          // Hook 过滤函数

}HOOK_DATA, * PHOOK_DATA;

#define HOOKLEN (5)         // 要改写的指令的长度
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
// Purpose:   取代原始MessageBoxA的功能,HOOK后所有对MessageBoxA的调用将实际调用本函数
// Author:    achillis
// Returns:   int WINAPI
// Parameter: HWND hWnd
// Parameter: LPCTSTR lpText
// Parameter: LPCTSTR lpCaption
// Parameter: UINT uType
//************************************
//注意函数的定义和原始函数一定要一样，尤其是调用约定，否则函数返回后将出错
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	//在这里，你可以对原始参数进行任意操作
	int ret;
	char newText[1024] = { 0 };
	char newCaption[256] = "pediy.com";
	printf("有人调用MessageBox!\n");
	//在调用原函数之前，可以对IN(输入类)参数进行干涉
	lstrcpy(newText, lpText);//为防止原函数提供的缓冲区不够，这里复制到我们自己的一个缓冲区中再进行操作
	lstrcat(newText, "\n\tMessageBox Hacked by pediy.com!");//篡改消息框内容
	uType |= MB_ICONERROR;//增加一个错误图标
	ret = OriginalMessageBox(hWnd, newText, newCaption, uType);//调用原MessageBox，并保存返回值
	//调用原函数之后，可以继续对OUT(输出类)参数进行干涉,比如网络函数的recv，可以干涉返回的内容
	return ret;//这里你还可以干涉原始函数的返回值
}


BOOL Inline_InstallHook(void)
{
	// 准备Hook,以下内容都是在准备 HOOK_DATA 结构体数据
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));        // 要 Hook 的目标模块及目标函数
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookCodeLen = 5;                        // Hook 指令的长度
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);        // 待 Hook 的地址
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;               // 调用原始跳板函数的通道
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;                       // Fake

	return InstallCodeHook(&MsgBoxHookData);
}

BOOL Inline_UnInstallHook()
{
	return UninstallCodeHook(&MsgBoxHookData);
}

/*
MessageBoxA 的代码开头
77D5050B >  8BFF                   mov edi,edi
77D5050D    55                     push ebp
77D5050E    8BEC                   mov ebp,esp
77D50510    833D 1C04D777 00       cmp dword ptr ds:[gfEMIEnable],0
*/
// 当需要调用原始的 MessageBox 时，直接调用此函数即可，参数完全相同
__declspec(naked)
int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	_asm
	{
		// 由于我们写入的 Jmp 指令破坏了原来的前 3 条指令，因此在这里执行原函数的前 3 条指令
		mov edi, edi      // 这一句可以不要
		push ebp
		mov ebp, esp
		jmp MsgBoxHookData.JmpBackAddr      // 跳到Hook代码之后的地方，绕过自己安装的Hook
	}

}

//获取指定模块中指定API的地址
LPVOID GetAddress(char* dllname, char* funname)
{
	HMODULE hMod = 0;
	if (hMod = GetModuleHandle(dllname))         // 经验证hMod不为空
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
   这里计算一下要填充的指令
   使用的是 5 字节的Jmp
*/
void InitHookEntry(PHOOK_DATA pHookData)
{
	if (pHookData == NULL
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->HookPoint == NULL)
	{
		return;
	}

	pHookData->newEntry[0] = 0xE9;      // Jmp，JMP 16位立即数值
	// 计算跳转偏移并写入
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;//0xE9 式jmp的计算
}


ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
	ULONG_PTR TrueAddress = 0;
	PBYTE pFn = (PBYTE)uAddress;

	if (memcmp(pFn, "\xFF\x25", 2) == 0)      // 函数使用 memcmp 函数来检查地址对应的前两个字节，看它们是否为 "\xFF\x25"。如果相同的话，表示该地址处的指令是跳转指令，接着函数会从地址中读取存储的跳转地址，并将其赋值给 TrueAddress。这个地址通常是一个间接跳转指令，意味着会跳转到存储在指定内存地址的目标地址。
	{
		TrueAddress = *(ULONG_PTR*)(pFn + 2);
		return TrueAddress;
	}
	if (pFn[0] == 0xE9)      // Long Jmp 的机器码，JMP 16位立即数值,       SkipJmpAddress(pHookData->pfnTrampolineFun);
	{
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;          // 长相对跳转指令偏移加 5 个字节
		return TrueAddress;
	}
	if (pFn[0] == 0xEB)      // JMP 8位立即数值
	{
		TrueAddress = (ULONG_PTR)pFn + pFn[1] + 2;         // 短相对跳转指令偏移加 2 个字节
		return TrueAddress;
	}
	printf("pFn[0] = 0x%x\n", pFn[0]);

	return (ULONG_PTR)uAddress;
}

// 注入 HOOK_DATA 数据到程序中，进行Hook攻击
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

	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);    // 走第二个分支
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);                 // 没有走任何分支，直接返回,返回的pFn[0]=0x8B,mov指令
	// 如果函数开头是跳转，那么将其跳过
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;

	InitHookEntry(pHookData);         // 填充 Inline Hook 代码
	//if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned)) , 这里导致代码出错了，是oldEntry
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))
	{
		if (WriteProcessMemory(hProcess,         // 要修改的进程内存句柄
			OriginalAddr,                        // 指向写入数据的指定进程中的基地址的指针
			pHookData->newEntry,                 // 指向缓冲区的指针
			pHookData->HookCodeLen,              // 要写入指定进程的字节数
			&dwBytesReturned))                   // 指向变量的指针
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





