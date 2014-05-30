// TestApiSetHookDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <commctrl.h>
#include "undocWM5.h"
#include "kernel.h"

TCHAR* szLogIO=L"\\Flash File Store\\fileio.txt";

typedef struct _CALLBACKINFO {
    HANDLE  hProc;      /* destination process */
    FARPROC pfn;        /* function to call in dest. process */
    PVOID   pvArg0;     /* arg0 data */
} CALLBACKINFO;
typedef CALLBACKINFO *PCALLBACKINFO;

extern"C" DWORD PerformCallBack4(CALLBACKINFO *pcbi,...);
extern"C" LPVOID MapPtrToProcess(LPVOID lpv, HANDLE hProc);
extern "C" BOOL SetKMode(BOOL bFlag);
extern "C" DWORD SetProcPermissions(DWORD dwPerms);

#define PUserKData ((LPBYTE)0xFFFFC800)
#define KINX_APISETS 24
//struct KDataStruct *KData =(KDataStruct*)PUserKdata;

#define FIRST_METHOD    0xF0010000
#define APICALL_SCALE   4
#define HANDLE_SHIFT 	8
#define METHOD_MASK 0x00FF
#define HANDLE_MASK 0x003F
#define PRIV_IMPLICIT_CALL(hid, mid) (FIRST_METHOD - ((hid)<<HANDLE_SHIFT | (mid))*APICALL_SCALE)


// we are hooking CreateFileW, 0xF000AFDC is exception call to this
// see name_wince_syscalls.idc
#define FAULT_ADDR 0xF000AFDC
//SH_FILESYS_APIS_RegOpenKeyExW
#define SH_FILESYS_APIS_RegOpenKeyExW 0xf000afa4

PFNVOID Old=0;

typedef HANDLE t_CreateFile(
  LPCTSTR lpFileName, 
  DWORD dwDesiredAccess, 
  DWORD dwShareMode, 
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
  DWORD dwCreationDisposition, 
  DWORD dwFlagsAndAttributes, 
  HANDLE hTemplateFile
); 

extern "C" HANDLE GetCallerProcess(void);

HANDLE _CreateFileHook(
  LPCTSTR lpFileName, 
  DWORD dwDesiredAccess, 
  DWORD dwShareMode, 
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
  DWORD dwCreationDisposition, 
  DWORD dwFlagsAndAttributes, 
  HANDLE hTemplateFile) 
{
	//get handle to original function
	HANDLE H=((t_CreateFile*)Old)(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);

	DWORD Err=GetLastError();
	if(_wcsicmp(szLogIO,lpFileName)==0 && H==INVALID_HANDLE_VALUE)
	{
		//in case of the log file is accessed or we got invalid handle
		H=((t_CreateFile*)Old)(szLogIO,GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,0,OPEN_ALWAYS,0,0);
		Err=GetLastError();
	} else
	{
		char Buff[1024]; 
		wchar_t Buff1[512];
		DWORD tmp;
		//get caller name
		GetModuleFileName((HMODULE)GetCallerProcess(), Buff1, 512);
		//HANDLE hOwner =GetOwnerProcess();
		if(H==INVALID_HANDLE_VALUE)
		{
			//log string for original CreateFile returned invalid handle
			sprintf(Buff,"%08X: CreateFileW(\"%S\",%x,%x,%x,%x,%x,%x) -> %08X, Err: %d (\"%S\")\n",
				GetCallerProcess(),
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile,
				H,
				Err,
				Buff1);
		} else 
		{
			//log string for original CreateFile returned a valid handle
			sprintf(Buff,"%08X: CreateFileW(\"%S\",%x,%x,%x,%x,%x,%x) -> %08X (\"%S\")\n",
				GetCallerProcess(),
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile,
				H,
				Buff1);
		}
		//open log file using original CreateFile
		HANDLE Out=((t_CreateFile*)Old)(szLogIO,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,
			0,OPEN_ALWAYS,0,0);
		//go to end
		SetFilePointer(Out,0,0,FILE_END);
		//write log string
		WriteFile(Out,Buff,strlen(Buff),&tmp,0);
		//close file
		CloseHandle(Out);
	}
	SetLastError(Err);
	return H; 
}

BOOL hookMethod(DWORD dwMethodID){
	BOOL bRet=FALSE;

	FILE *F=fopen("\\log.txt","at");
	HANDLE Out=INVALID_HANDLE_VALUE;

	BOOL bMode = SetKMode(TRUE);
    DWORD dwPerm = SetProcPermissions(0xFFFFFFFF);
	CINFO **SystemAPISets= (CINFO **)KData.aInfo[KINX_APISETS];

	//DWORD Tmp= (FIRST_METHOD - FAULT_ADDR)/APICALL_SCALE;  
	DWORD Tmp= (FIRST_METHOD - dwMethodID)/APICALL_SCALE;  
	DWORD ApiSet=(Tmp>>HANDLE_SHIFT)&HANDLE_MASK;
    DWORD Method=Tmp&METHOD_MASK;

	// validate
	if(ApiSet>NUM_SYSTEM_SETS)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid ApiSet",F);
		fclose(F);
		return FALSE;
	}
	if(SystemAPISets[ApiSet]==0)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid ApiSet",F);
		fclose(F);
		return FALSE;
	}
	if(SystemAPISets[ApiSet]->cMethods <= Method)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid method number",F);
		fclose(F);
		return FALSE;
	}

	if(SystemAPISets[ApiSet]->pServer==0)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Calls with pServer==0 are not supported",F);
		fclose(F);
		return FALSE; 
	}
	// ppfnMethods sometimes is located in ROM, relocate to RAM to make it writeable
	void **NewMethods=(void**)malloc(4*SystemAPISets[ApiSet]->cMethods);
	memcpy(NewMethods,SystemAPISets[ApiSet]->ppfnMethods,4*SystemAPISets[ApiSet]->cMethods);

	F=fopen("\\log.txt","at");
	fprintf(F,"Before moving table\n");
	fflush(F);

	//open log file as out
	Out=CreateFile(szLogIO,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,
		0,OPEN_ALWAYS,0,0);
	//jump to end of out file
	SetFilePointer(Out,0,0,FILE_END);

	//map pointer to our process
	SystemAPISets[ApiSet]->ppfnMethods=(PFNVOID*)MapPtrToProcess(NewMethods,GetCurrentProcess());

	//save old pointer to method
	Old=SystemAPISets[ApiSet]->ppfnMethods[Method];
	//replace method by our hooked method
	SystemAPISets[ApiSet]->ppfnMethods[Method]=(PFNVOID)_CreateFileHook;

	fprintf(F,"Hooked!\n");	
	fclose(F);

	DWORD tmp;
	WriteFile(Out,"Hooked CreateFileW...\n",strlen("Hooked CreateFileW...\n"),&tmp,0);
	CloseHandle(Out);

	SetKMode(bMode);
    SetProcPermissions(dwPerm);

	return TRUE;
}

extern "C" __declspec(dllexport)
BOOL PerformHook(HMODULE t)
{
	static bool Hooked=false;
	HANDLE Out=INVALID_HANDLE_VALUE;
	FILE *F=fopen("\\log.txt","at");
	fprintf(F,"PerformHook: %08X, %08X\n",GetCurrentProcessId(),t);
	fclose(F);
	printf("t=%08x\n",t);
	if((DWORD)t!=(DWORD)GetCurrentProcessId())	// debugging: be sure that we are called from correct process
	{
		FILE *F=fopen("\\log.txt","at");
		fprintf(F,"!=%08x\n",GetCurrentProcessId());
		fclose(F);
		return TRUE;
	}
	if(Hooked) 
	{ 
		FILE *F=fopen("\\log.txt","at");
		fputs("Already hooked",F);
		fclose(F);
		return TRUE;
	}
	Hooked=true;

	//BOOL bRes = hookMethod(FAULT_ADDR);

	
	BOOL bMode = SetKMode(TRUE);
    DWORD dwPerm = SetProcPermissions(0xFFFFFFFF);
	CINFO **SystemAPISets= (CINFO **)KData.aInfo[KINX_APISETS];

	DWORD Tmp= (FIRST_METHOD-FAULT_ADDR)/APICALL_SCALE;  
	DWORD ApiSet=(Tmp>>HANDLE_SHIFT)&HANDLE_MASK;
    DWORD Method=Tmp&METHOD_MASK;

	// validate
	if(ApiSet>NUM_SYSTEM_SETS)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid ApiSet",F);
		fclose(F);
		return 0;
	}
	if(SystemAPISets[ApiSet]==0)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid ApiSet",F);
		fclose(F);
		return 0;
	}
	if(SystemAPISets[ApiSet]->cMethods <= Method)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Invalid method number",F);
		fclose(F);
		return 0;
	}

	if(SystemAPISets[ApiSet]->pServer==0)
	{
		FILE *F=fopen("\\log.txt","at");
		fputs("Calls with pServer==0 are not supported",F);
		fclose(F);
		return 0; 
	}
	// ppfnMethods sometimes is located in ROM, relocate to RAM to make it writeable
	void **NewMethods=(void**)malloc(4*SystemAPISets[ApiSet]->cMethods);
	memcpy(NewMethods,SystemAPISets[ApiSet]->ppfnMethods,4*SystemAPISets[ApiSet]->cMethods);

	F=fopen("\\log.txt","at");
	fprintf(F,"Before moving table\n");
	fflush(F);

	//open log file as out
	Out=CreateFile(szLogIO,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,
		0,OPEN_ALWAYS,0,0);
	//jump to end of out file
	SetFilePointer(Out,0,0,FILE_END);

	//map pointer to our process
	SystemAPISets[ApiSet]->ppfnMethods=(PFNVOID*)MapPtrToProcess(NewMethods,GetCurrentProcess());

	//save old pointer to method
	Old=SystemAPISets[ApiSet]->ppfnMethods[Method];
	//replace method by our hooked method
	SystemAPISets[ApiSet]->ppfnMethods[Method]=(PFNVOID)_CreateFileHook;

	fprintf(F,"Hooked!\n");	
	fclose(F);

	DWORD tmp;
	WriteFile(Out,"Hooked CreateFileW...\n",strlen("Hooked CreateFileW...\n"),&tmp,0);
	CloseHandle(Out);

	SetKMode(bMode);
    SetProcPermissions(dwPerm);
	

	return TRUE;
} 

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	FILE *F=fopen("\\log.txt","at");
	fprintf(F,"DllMain: %08X, %d\n",GetCurrentProcessId(),ul_reason_for_call);
	fclose(F);
    return TRUE;
}


