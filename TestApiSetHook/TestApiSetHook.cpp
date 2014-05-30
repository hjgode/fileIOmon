// TestApiSetHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <commctrl.h>
#include "undocWM5.h"
#include "kernel.h"



typedef struct _CALLBACKINFO {
    HANDLE  hProc;      /* destination process */
    FARPROC pfn;        /* function to call in dest. process */
    PVOID   pvArg0;     /* arg0 data */
} CALLBACKINFO;
typedef CALLBACKINFO *PCALLBACKINFO;

extern"C" DWORD PerformCallBack4(CALLBACKINFO *pcbi,...);
extern"C" LPVOID MapPtrToProcess(LPVOID lpv, HANDLE hProc);

extern"C" LPVOID MapPtrToProcess(LPVOID lpv, HANDLE hProc);
extern "C" BOOL SetKMode(BOOL bFlag);
extern "C" DWORD SetProcPermissions(DWORD dwPerms);

#define PUserKData ((LPBYTE)0xFFFFC800)
#define KINX_APISETS 24
//struct KDataStruct *KData =(KDataStruct*)PUserKdata;
// 0  = SH_WIN32
// 1  = SH_CURTHREAD
// 2  = SH_CURPROC
// 3  = SH_KWIN32
// 4  = HT_EVENT
// 5  = HT_MUTEX
// 6  = HT_APISET
// 7  = HT_FILE
// 8  = HT_FIND
// 9  = HT_DBFILE
// 10 = HT_DBFIND
// 11 = HT_SOCKET
// 12 = HT_INTERFACE
// 13 = HT_SEMAPHORE
// 14 = HT_FSMAP
// 15 = HT_WNETENUM

TCHAR* APISETNAMES[] = { L"SH_WIN32", L"SH_CURTHREAD", L"SH_CURPROC", L"SH_KWIN32", L"HT_EVENT", L"HT_MUTEX", L"HT_APISET", L"HT_FILE", L"HT_FIND", L"HT_DBFILE", L"HT_DBFIND", L"HT_SOCKET", L"HT_INTERFACE", L"HT_SEMAPHORE", L"HT_FSMAP", L"HT_WNETENUM" }; 

#define FIRST_METHOD    0xF0010000
#define APICALL_SCALE   4
#define HANDLE_SHIFT 	8
#define METHOD_MASK 0x00FF
#define HANDLE_MASK 0x003F
#define PRIV_IMPLICIT_CALL(hid, mid) (FIRST_METHOD - ((hid)<<HANDLE_SHIFT | (mid))*APICALL_SCALE)


// FAULT_ADDR is address of trap that is called on a function we need to hook, in this case CreateFile. 
#define FAULT_ADDR 0xF000AFA4

HANDLE _CreateFileHook()
{
	return INVALID_HANDLE_VALUE;
}

void nclog (const wchar_t *fmt, ...)
{
    va_list vl;
    va_start(vl,fmt);
	wchar_t bufW[1024]; // to bad CE hasn't got wvnsprintf
	wvsprintf(bufW,fmt,vl);
	DEBUGMSG(1, (bufW));
}

int _tmain(int argc, _TCHAR* argv[])
{
	BOOL bMode = SetKMode(TRUE);
    DWORD dwPerm = SetProcPermissions(0xFFFFFFFF);

	CINFO **SystemAPISets= (CINFO **)KData.aInfo[KINX_APISETS];
	for(int i=0; i<NUM_SYSTEM_SETS; i++)
	{
		nclog(L"SystemAPISets[%d]:\n",i);
		nclog(L"API set: %s\n", APISETNAMES[i]);
		if(SystemAPISets[i]==0)
		{
			nclog(L"  NULL\n");
			continue;
		}
		nclog(L"  acName: %s\n",SystemAPISets[i]->acName);
		nclog(L"  cMethods: %d\n",SystemAPISets[i]->cMethods);
		nclog(L"\n");
	}

	DWORD Tmp= (FIRST_METHOD-FAULT_ADDR)/APICALL_SCALE;  
	DWORD ApiSet=(Tmp>>HANDLE_SHIFT)&HANDLE_MASK;
    DWORD Method=Tmp&METHOD_MASK;

	// validate
	if(ApiSet>NUM_SYSTEM_SETS)
	{
		nclog(L"Invalid ApiSet\n");
		return 0;
	}
	if(SystemAPISets[ApiSet]==0)
	{
		nclog(L"Invalid ApiSet\n");
		return 0;
	}
	if(SystemAPISets[ApiSet]->cMethods<=Method)
	{
		nclog(L"Invalid method number\n");
		return 0;
	}

	// I support only filesystem and similar hooks that are processed inside filesys.exe
	if(SystemAPISets[ApiSet]->pServer==0)
	{
		nclog(L"Calls with pServer==0 are not supported\n");
		return 0;
	}

	// get server process and inject DLL there
	HANDLE Proc=SystemAPISets[ApiSet]->pServer->hProc;

	void *Ptr=MapPtrToProcess(L"TestApiSetHookDll.dll",GetCurrentProcess());
    CALLBACKINFO ci;
	ci.hProc=Proc;
	void *t=GetProcAddress(GetModuleHandle(L"coredll.dll"),L"LoadLibraryW");
	ci.pfn=(FARPROC)MapPtrToProcess(t,Proc);
	ci.pvArg0=Ptr;
	PerformCallBack4(&ci);
	Sleep(1000);	// allow PerformCallBack4 to finish before exit. Better enum loaded DLLs or use events

	// bug in VS2005b1 causes DllMain not to be called in DLLs
	HMODULE Hm=LoadLibrary(L"TestApiSetHookDll.dll");
	void *Fn=GetProcAddress(Hm,L"PerformHook");
	if(Hm==0 || Fn==0)
	{
		nclog(L"Unable to load library\n");
		return 0;
	}
	ci.hProc=Proc;
	ci.pfn=(FARPROC)MapPtrToProcess(Fn,Proc);
	ci.pvArg0=Proc;			// pass the hooked process ID as parameter to be sure that we are called from the context of hooked process
	PerformCallBack4(&ci);	// so we call function ourselves, fortunately DLLs are loaded at the same address in all processes
	Sleep(3000);	

	nclog(L"exit\n");
	MessageBox(GetForegroundWindow(),L"CreateFileW hooked!",L"Done",0);
	FreeLibrary(Hm);
	return 0;
}

