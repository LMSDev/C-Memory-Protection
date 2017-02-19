#include <Windows.h>
#include <iostream>
#include "VirtualMachine.h"
#include "macros.h"

using namespace std;

class Test
{
public:
	static void ValidateDataStream(CallContext callContext);
};

VirtualMachine* vm;
void PrintNumber(CallContext callContext);
void SleepAndClear(CallContext callContext);
void CheckForDebugger(CallContext callContext);
void ProtectMemory(CallContext callContext);

// Protection shit
int GetProcAddr(char* dll, char* name);
__declspec(noinline) HMODULE WINAPI LoadLibraryWrapper(LPCWSTR lpLibFilename);
void GetProcAsm();
__declspec(noinline) void Encrypt(char* dst, int maxSize);
LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers);
bool HideThread(HANDLE hThread);
inline bool CheckOutputDebugString(LPCTSTR String);
bool IsDbgPresentPrefixCheck();
inline bool DebugObjectCheck();

int globals[] = { (int)PrintNumber, (int)SleepAndClear, (int)ProtectMemory };
int globals1[] = { 0, (int)CheckForDebugger };
int globals2[] = { 1337, (int)Test::ValidateDataStream };
int* _globals[] = { globals, globals1, globals2 };

#define JUNK_CODE_ONE        \
    __asm{push eax}            \
    __asm{xor eax, eax}        \
    __asm{setpo al}            \
    __asm{push edx}            \
    __asm{xor edx, eax}        \
    __asm{sal edx, 2}        \
    __asm{xchg eax, edx}    \
    __asm{pop edx}            \
    __asm{or eax, ecx}        \
    __asm{pop eax}

#define JUNK_CODE_TWO \
__asm{push eax} \
 __asm{xor eax, eax} \
__asm{mov eax,12} \
__asm{pop eax}

#define THE_VALUE 1337

#ifdef OBFUSCATE
		int data[] = { 
		// OPCODE	// HASH		SIZE	STORED	OFFSET	GLOBALS	PARAMETER
		-0x2,		0x1337,		0,		0,		0,		1,		0,					// LABEL 0 = Store label in slot 0 (we use globals 1 here)
		-0x4,		0x1337,		0,		0,		0,		2,		0,		THE_VALUE,	// STORE 1337 GLOBALS2[0] = Store 1337 in globals2 at slot 0
		-0x7,		0x1337,		0,		0,		0,		2,		0,					// LOAD GLOBALS2[0] = Load variable from globals 2 slot 0
		-0x6,		0x1337,		0,		0,		0,		0,							// PUSH = Push loaded variable onto stack
		-0x1,		0x55,		0x1,	0,		0,		1,		1,					// CALL GLOBALS1[1]		(CheckForDebugger)
		-0x8,		0x1337,		0,		0,		0,		0,		10,					// INT3 (we pass a parameter to break the offset after being executed)
		-0x1,		0x55,		0x1,	0,		0,		2,		1,					// CALL GLOBALS2[1]			(ValidateDataStream)
/*CHANGED*/-0x6,		0x1337,		0x6,		0,		0,		0,		0,					// CALLS 0 = Call 0 from globals0 using stack (PrintNumber)
		-0x1,		0x55,		0x1,	0,		0,		0,		1,		10,			// CALL 1 10 = Call second function with 10 as param (we use globals 0 here) (SleepAndClear)
		-0x1,		0x55,		0x1,	0,		0,		0,		2,					// CALL globals0[2] = ProtectMemory
/*GLOBALS CHANGED*/		-0x3,		0x1337,		0,		0,		0,		2,		0,					// JMP 0 = Jump to label 0 (we use globals 1 here)


		-0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD	// END
	};
#elif !OBFUSCATE
		int data[] = { 
		// OPCODE	// HASH		SIZE	STORED	OFFSET	GLOBALS	PARAMETER
		-0x2,		0x1337,		0,		0,		0,		1,		0,					// LABEL 0 = Store label in slot 0 (we use globals 1 here)
		-0x4,		0x1337,		0,		0,		0,		2,		0,		1337,		// STORE 1337 GLOBALS2[0] = Store 1337 in globals2 at slot 0
		//-0x1,		0x1337,		0,		0,		0,		0,		0,		1337,		// CALL 0 1337 = Call first function with 1337 as param (we use globals 0 here)
		-0x7,		0x1337,		0,		0,		0,		2,		0,					// LOAD GLOBALS2[0] = Load variable from globals 2 slot 0
		-0x6,		0x1337,		0,		0,		0,		0,							// PUSH = Push loaded variable onto stack
		-0x1,		0x482,		0x8,	0,		0,		1,		1,					// CALL GLOBALS1[1]		(CheckForDebugger)
		-0x8,		0x1337,		0,		0,		0,		0,		10,					// INT3 (we pass a parameter to break the offset after being executed)
		-0x1,		0x482,		0x8,	0,		0,		2,		1,					// CALL GLOBALS2[1]		(ValidateDataStream)
		-0x5,		0x1337,		0,		0,		0,		0,		0,					// CALLS 0 = Call 0 from globals0 using stack (PrintNumber)
		-0x1,		0x482,		0x8,	0,		0,		0,		1,		10,			// CALL 1 10 = Call second function with 10 as param (we use globals 0 here) (SleepAndClear)
		-0x1,		0x482,		0x8,		0,		0,		0,		2,					// CALL globals0[2] = ProtectMemory
		-0x3,		0x1337,		0,		0,		0,		1,		0,					// JMP 0 = Jump to label 0 (we use globals 1 here)


		-0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD	// END
	};

#endif

int main()
{	
	FindWindowA("", NULL);

	// Force load DLL
	FindWindowA("", NULL);

	// Create VM
	vm = new VirtualMachine();
	vm->Initialize((void*)data, sizeof(data));

	for (int i = 0; i < 3; i++)
	{
		vm->AddGlobals(_globals[i]);
	}

	//_globals[2][0] = 1337;

	while (true)
	{
		if (!vm->Run())
		{
			break;
		}
	}

	vm->Shutdown();
	delete vm;
	vm = NULL;
}

void PrintNumber(CallContext callContext)
{
	cout << callContext.arguments[1];

#ifdef OBFUSCATE
	vm->AdjustInstructionCode(-0x1);
#endif

	// Adjust (two arguments)
	vm->AdjustDataOffset(0);
}

void SleepAndClear(CallContext callContext)
{
	Sleep(callContext.arguments[1]);
	system("cls");

	// Adjust (two arguments)
	vm->AdjustDataOffset(8);
}

void Test::ValidateDataStream(CallContext callContext)
{
	// Undone at the end
	vm->AdjustCallTarget(-1);

	// Perform anti debugging check
#ifdef OBFUSCATE
	_asm
	{
		MOV		ebx, DWORD PTR FS:[18h]
		ADD		ebx, 13h // === Useless; add 10h to TEB
		MOV ebx, DWORD PTR DS:[ebx+1Dh] // === PEB; would be MOV EAX, DWORD PTR DS:[EAX+30] if we hadn't already added 10
		MOVZX ebx, BYTE PTR DS:[ebx+2] 
		test	ebx, ebx
		jz		NoDebugger
	}
	return;
#endif

	NoDebugger:

	// Hash is different when obfuscated data is used. We subtract the hash of the data
#ifdef OBFUSCATE
	vm->AdjustDataOffset(-34778 - THE_VALUE);
	vm->AdjustCallTarget(0x5);
#elif !OBFUSCATE
	vm->AdjustDataOffset(-40413);
#endif

	JUNK_CODE_ONE
#ifdef OBFUSCATE
	HideThread(NULL);
#endif
	int* data = (int*)vm->GetDataStream();

	// Hash
	int hash = 0;
	for (int i = 0; i < 80; i++)
	{
		hash += data[i];
	}

	// We add the hash of the data back. If data has been changed, offset will be wrong
	vm->AdjustDataOffset(hash + 4);

	// If obfuscated, this is needed in order to turn the next instruction in the data into a valid one
#ifdef OBFUSCATE
	vm->AdjustInstructionCode(0x1);
#endif

	// If no differnce, 1 will be added. If there is a difference, 0 will be added
	int difference = _globals[2][0] == THE_VALUE;
	vm->AdjustCallTarget(difference);
}

void CheckForDebugger(CallContext callContext)
{
	// Skip own argument
	vm->AdjustDataOffset(4);

	char ollyDbg[] = "DGGROIL";

	char className[] = "\\beod|"; // "Window";
	char cheatEngine60Name[] = "Hcnj+Nelben+=%;"; ////"Cheat Engine 6.0";
	char cheatEngine61Name[] = "Hcnj+Nelben+=%:"; ////"Cheat Engine 6.1";
	char cheatEngine62Name[] = "Hcnj+Nelben+=%9"; ////"Cheat Engine 6.2";
	char cheatEngine63Name[] = "Hcnj+Nelben+=%8"; ////"Cheat Engine 6.3";
	Encrypt(className, sizeof(className));
	Encrypt(cheatEngine60Name, sizeof(cheatEngine60Name));
	Encrypt(cheatEngine61Name, sizeof(cheatEngine61Name));
	Encrypt(cheatEngine62Name, sizeof(cheatEngine62Name));
	Encrypt(cheatEngine63Name, sizeof(cheatEngine63Name));

	JUNK_CODE_ONE

	char user32Dll[] = "^xny89%ogg";
	char FindWindowA[] = "Mbeo\\beod|J";
	char GetWindowTextA[] = "Ln\\beod|_nsJ";
	Encrypt(user32Dll, sizeof(user32Dll));
	Encrypt(FindWindowA, sizeof(FindWindowA));
	Encrypt(GetWindowTextA, sizeof(GetWindowTextA));

	HWND (WINAPI *address)(LPCSTR, LPCSTR) = (HWND (WINAPI*)(LPCSTR, LPCSTR))GetProcAddr(user32Dll, FindWindowA);
	HWND cheatEngineWindow = address(className, NULL);
	if (cheatEngineWindow != NULL)
	{
		char windowText[128] = {};
		int (WINAPI *address2)(HWND, LPSTR, int) = (int (WINAPI*)(HWND, LPSTR, int))GetProcAddr(user32Dll, GetWindowTextA);
		address2(cheatEngineWindow, windowText, sizeof(windowText));
		if (strcmp(windowText, cheatEngine60Name) == 0 ||
			strcmp(windowText, cheatEngine61Name) == 0 ||
			strcmp(windowText, cheatEngine62Name) == 0 ||
			strcmp(windowText, cheatEngine63Name) == 0)
		{
			return;
		}
	}

	Encrypt(ollyDbg, sizeof(ollyDbg));

	if (address(ollyDbg, NULL) != NULL)
	{
		return;
	}

	// Skip half of instruction INT 3 (20 bytes)
	vm->AdjustDataOffset(_globals[2][0] - (THE_VALUE - 20));
#ifdef OBFUSCATE
	if (DebugObjectCheck())
	{
		vm->AdjustInstructionCode(0x3);
	}
#endif

	JUNK_CODE_ONE

	// Skip other half of instruction INT 3 (8 bytes)
	vm->AdjustDataOffset(8 + IsDbgPresentPrefixCheck());
}

void ProtectMemory(CallContext callContext)
{
	typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *pSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter); 

	char kernel32[] = "`nyeng89%ogg";
	char SetUnhandledExceptionFilter[] = "Xn^ecjeognoNshn{bdeMbgny";
	Encrypt(kernel32, sizeof(kernel32));
	Encrypt(SetUnhandledExceptionFilter, sizeof(SetUnhandledExceptionFilter));

#ifdef OBFUSCATE
	// Changed back in hide thread
	vm->AdjustCallTarget(0x5);

	// Since data is changed, we have to adjust the globals here
	vm->AdjustGlobalsOffset(-0x1);
		((pSetUnhandledExceptionFilter)GetProcAddr(kernel32, SetUnhandledExceptionFilter))(UnhandledExcepFilter);
    __asm{xor eax, eax}
    __asm{div eax}
#endif

	JUNK_CODE_TWO
#ifdef OBFUSCATE
	HideThread(NULL);
#endif
	JUNK_CODE_ONE

	// Skip own argument
	vm->AdjustDataOffset(4);
}

LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
	typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *pSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter); 

	char kernel32[] = "`nyeng89%ogg";
	char SetUnhandledExceptionFilter[] = "Xn^ecjeognoNshn{bdeMbgny";
	Encrypt(kernel32, sizeof(kernel32));
	Encrypt(SetUnhandledExceptionFilter, sizeof(SetUnhandledExceptionFilter));

	JUNK_CODE_TWO

	// Restore old UnhandledExceptionFilter
	((pSetUnhandledExceptionFilter)GetProcAddr(kernel32, SetUnhandledExceptionFilter))((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);


    // Skip the exception code
    pExcepPointers->ContextRecord->Eip += 2;

    return EXCEPTION_CONTINUE_EXECUTION;
}

// HideThread will attempt to use
// NtSetInformationThread to hide a thread
// from the debugger, Passing NULL for
// hThread will cause the function to hide the thread
// the function is running in. Also, the function returns
// false on failure and true on success
__forceinline bool HideThread(HANDLE hThread)
{
    typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG); 
    NTSTATUS Status; 

	typedef HANDLE (WINAPI *pGetCurrentThread)(void); 

	char ntdll[] = "eogg%ogg";
	char NtSetInformationThread[] = "EXnBemdyfjbde_cynjo";
	Encrypt(ntdll, sizeof(ntdll));
	Encrypt(NtSetInformationThread, sizeof(NtSetInformationThread));

	char kernel32[] = "`nyeng89%ogg";
	char GetCurrentThread[] = "LnH~yyne_cynjo";
	Encrypt(kernel32, sizeof(kernel32));
	Encrypt(GetCurrentThread, sizeof(GetCurrentThread));

	JUNK_CODE_TWO

    // Get NtSetInformationThread
    pNtSetInformationThread NtSIT = (pNtSetInformationThread)GetProcAddr(ntdll, NtSetInformationThread);
	pGetCurrentThread getCurrentThread = (pGetCurrentThread)GetProcAddr(kernel32, GetCurrentThread);

	JUNK_CODE_TWO

    // Set the thread info
    if (hThread == NULL)
	{
		JUNK_CODE_ONE
		vm->AdjustCallTarget(-0x5);
        Status = NtSIT(getCurrentThread(), 0x11, 0, 0); // HideThreadFromDebugger
	}
    else
	{
		vm->AdjustCallTarget(-0x5);
        Status = NtSIT(hThread, 0x11, 0, 0); 
	}


    if (Status != 0x00000000)
        return false;
    else
        return true;
}

// CheckOutputDebugString checks whether or 
// OutputDebugString causes an error to occur
// and if the error does occur then we know 
// there's no debugger, otherwise if there IS
// a debugger no error will occur
inline bool CheckOutputDebugString(LPCTSTR String)
{
	return false;
	char kernel32[] = "`nyeng89%ogg";
	char OutputDebugStringW[] = "D~{~Oni~lXybel\\";
	char GetLastError[] = "LnGjxNyydy";
	Encrypt(kernel32, sizeof(kernel32));
	Encrypt(OutputDebugStringW, sizeof(OutputDebugStringW));
	Encrypt(GetLastError, sizeof(GetLastError));

	typedef void (WINAPI *pOutputDebugString)(PCTSTR lpOutputString);
	(((pOutputDebugString)GetProcAddr(kernel32, OutputDebugStringW))(String));

	JUNK_CODE_TWO

	typedef DWORD (WINAPI *pGetLastError)(void);

    if ((((pGetLastError)GetProcAddr(kernel32, GetLastError))()) == 0)
        return true;
    else
        return false;
}

// This function uses NtQuerySystemInformation
// to try to retrieve a handle to the current
// process's debug object handle. If the function
// is successful it'll return true which means we're
// being debugged or it'll return false if it fails
// or the process isn't being debugged
__forceinline bool DebugObjectCheck()
{
    // Much easier in ASM but C/C++ looks so much better
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
            (HANDLE ,UINT ,PVOID ,ULONG , PULONG); 

	typedef HANDLE (WINAPI *pGetCurrentProcess)(void);

    HANDLE hDebugObject = NULL;
    NTSTATUS Status; 

	char ntdll[] = "eogg%ogg";
	char NtQueryInformationProcess[] = "EZ~nyrBemdyfjbde[ydhnxx";
	char GetCurrentProcess[] = "LnH~yyne[ydhnxx";
	char kernel32[] = "`nyeng89%ogg";
	Encrypt(ntdll, sizeof(ntdll));
	Encrypt(NtQueryInformationProcess, sizeof(NtQueryInformationProcess));
	Encrypt(GetCurrentProcess, sizeof(GetCurrentProcess));
	Encrypt(kernel32, sizeof(kernel32));

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddr(ntdll, NtQueryInformationProcess);
	pGetCurrentProcess GetCurrProc = (pGetCurrentProcess)GetProcAddr(kernel32, GetCurrentProcess);

    Status = NtQIP(GetCurrProc(), 
            0x1e, // ProcessDebugObjectHandle
            &hDebugObject, 4, NULL); 
    
    if (Status != 0x00000000)
        return false; 

    if(hDebugObject)
        return true;
    else
        return false;
}

// The IsDbgPresentPrefixCheck works in at least two debuggers
// OllyDBG and VS 2008, by utilizing the way the debuggers handle
// prefixes we can determine their presence. Specifically if this code
// is ran under a debugger it will simply be stepped over;
// however, if there is no debugger SEH will fire :D
__forceinline bool IsDbgPresentPrefixCheck()
{
#ifdef OBFUSCATE
    __try
    {
		__asm pushad
		__asm popad
        __asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
        __asm __emit 0x64
        __asm __emit 0xF1 // One byte INT 1
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    return true;
#elif !OBFSUCATE
		return false;
#endif
}

int __cdecl GetProcAddr(char* dll, char* name)
{
	int address = 0;
	_asm
	{
		push dll
		push name
		call GetProcAsm
		mov	address, eax
	}

	return address;
}

__declspec(noinline) HMODULE WINAPI LoadLibraryWrapper(LPCWSTR lpLibFilename)
{
	return 0;
	//return LoadLibraryW(lpLibFilename);
}

__declspec(naked) __forceinline void GetProcAsm()
{
	_asm
	{
       add    esp,-2*4-4*4              ; room for 4 registers and 2 local variables
       mov    [esp+2*4+0*4], edi        ; saving registers
       mov    [esp+2*4+1*4], ebp        ;
       mov    [esp+2*4+2*4], esi        ;
       mov    [esp+2*4+3*4], ebx        ;
       mov    dword ptr [esp+1*4], 0    ; [esp+1*4]-> clear flag for forwarded proc
GetStart:                               ;
       mov    edx, [esp+2*4+4*4+2*4]    ; edx->lp Dll name
       mov    ebp, 20h                  ; ebp-> BaseDllName address (Unicode)
       cmp    byte ptr [edx+1], 3Ah     ; "c:\...." Is it full path or just dll name?
       jne    a                        ;
       mov    ebp, 18h                  ; ebp-> FullDllName (Unicode)
a:                                     ;
; Get module base address...............;
       mov    eax, fs:[30h]             ; PEB base in eax
       cmp    dword ptr [esp+1*4], -1   ; If it is forwarded esi->ntdll.dll
       mov    eax, [eax+0Ch]            ; eax-> PEB_LDR_DATA
       mov    edi, edx                  ; edi->lp Dll name
       mov    esi, [eax+1Ch]            ; esi-> 1st entry in InitOrderModuleList
       je     b                        ; else
       mov    esi, [esi]                ; esi->Kernel32.dll
b:                                     ;
       mov    eax, [esi+ebp]            ; eax-> BaseDllName or FullDllName (Unicode)
       mov    ebx, esi                  ; ebx-> the 1st LDR_MODULE in the chain
; Comparing strings ....................;
                                        ;
FindNextCharw:                          ;
       mov    ch,  [eax]                ; eax-> BaseDllName or FullDllName (Unicode)
       add    eax, 2                    ;
       cmp    ch,  5Ah                  ;
       ja     c                        ;
       cmp    ch,  41h                  ;
       jl     c                        ;
       or     ch,  20h                  ;
c:                                     ;
       mov    cl,  [edx]                ; edx->lp dll name string "." or zero ended
       add    edx, 1                    ;
       cmp    cl,  5Ah                  ;
       ja     d                        ;
       cmp    cl,  41h                  ;
       jl     d                        ;
       or     cl,  20h                  ;
d:                                     ;
       cmp    cl,  ch                   ;
       jne    Next_LDRw                 ;
       test   ch,  ch                   ;
       je     e                        ;
       cmp    ch,  2Eh                  ; "."
       jne    FindNextCharw             ;
       cmp    dword ptr [esp+1*4], -1   ; flag for forwarded proc ->  If it is forwarded
       jne    FindNextCharw             ;           copy until "." , else until zero
e:                                     ;
       mov    ebx, [esi+8]              ; ebx-> Base Dll Name address
       je     GetNextApi                ;
                                        ;
; Next forward LDR_MODULE ..............;
Next_LDRw:                              ;
       mov    esi, [esi]                ; we go forwards
       mov    edx, edi                  ; edx->lp Dll name
       mov    eax, [esi+ebp]            ; eax-> BaseDllName or FullDllName (Unicode) address
	   test   eax, eax
	   jz	  Next_LDRw
	   cmp    ebx, esi                  ; If current module = 1st module -> Dll is Not Loaded
       jne    FindNextCharw             ;
                                        ; 
; The module is not loaded in memory and;
; we will try LoadLibrary to load it....;
	jmp End_NotFound	                ;  Disabled for now
       cmp    dword ptr [esp+1*4],-1    ; If it is forwarded
       je     Forwarded_Dll             ; copy dll name in the stack and call oadLibrary
       xor    ebx, ebx                  ; ebx = 0
	   push		edx
       call LoadLibraryWrapper          ; call API
       add    ebx, eax                  ; ebx-> BaseDllName address or zero
       je     End_NotFound              ; No such dll -> exit with ebx=0-> error
; End of Get module base address........;
                                        ;
GetNextApi:                             ;
       mov    edx, [ebx+3Ch]            ; edx-> beginning of PE header
       mov    esi, ebx                  ; ebp-> current dll base address
       mov    edi, [ebx+edx+78h]        ; edi-> RVA of ExportDirectory -> 78h
       mov    ecx, [ebx+edx+7Ch]        ; ecx-> RVA of ExportDirectorySize ->7Ch
       add    esi, [ebx+edi+20h]        ; esi-> AddressOfNames ->20h
       add    edi, ebx                  ; ebx-> current dll base address
       movd   MM5, edi                  ; MM5-> edi-> ExportDirectory
       mov    ebp, [esp+1*4+(4*4+2*4)]  ; ebp->proc name address or ordinal value
       add    ecx, edi                  ; ecx= ExportDirectory address + ExportDirectorySize
       mov    eax, [edi+18h]            ; eax = num of API Names-> nMax NumberOfNames->18h
       test   ebp, 0ffff0000h           ; is it proc name address or ordinal value?
       mov    [esp+0*4], ecx            ; [esp+0*4] = ExportDirectory address + ExportDirectorySize
       je     GetByOrdinal              ;GetProcAddress by Ordinal
                                        ;   
; Binary search ........................;GetProcAddress by Name
       movd   MM7, esp                  ; save the stack here
       movzx  ecx, byte ptr [ebp]       ; ebp->proc name address
       lea    edi, [esi+4]              ;      cl-> 1st character of the proc name 
       mov    esp, ebx                  ; esp-> current dll base address
       neg    edi                       ; set carry flag
       movd   MM6, edi                  ; MM6= -(esi+4]
Bin_Search:                             ; 
      ;cmova  esi, edx                  ; see Note 1
       sbb    edi, edi                  ; edi->mask  -1 or 0
       xor    esi, edx                  ; mix esi and edx
       and    esi, edi                  ; esi=esi or esi=0
       mov    ebx, esp                  ; ebx-> current dll base address
       xor    esi, edx                  ; esi=esi or esi=edx
       shr    eax, 1                    ;
       je     End_ZeroIndex             ;
IndexIsZero:                            ;
       add    ebx, [esi+4*eax]          ;
       lea    edx, [esi+4*eax+4]        ;
       cmp    cl,  [ebx]                ; ebx-> API Names Table 
       jne    Bin_Search                ;
; End Binary search ....................;
                                        ;
; Compare next bytes of two strings.....;
       lea    edi, [ebp+1]              ;     
f:                                     ;
       mov    ch,  [edi]                ; comparing bytes   
       add    ebx, 1                    ;   
       cmp    ch,  [ebx]                ; ebx-> API Names Table 
       jne    Bin_Search                ;
       add    edi, 1                    ;   
       test   ch,  ch                   ;   
       jne    f                        ;
                                        ;
; Extract the index from EDX to get proc address   
       movd   esi, MM5                  ; esi-> ExportDirectory
       movd   eax, MM6                  ; eax-> -(AddressOfNames+4)
       mov    edi, [esi+24h]            ; edi->AddressOfNameOrdinals ->24h
       mov    ecx, esp                  ; ecx-> current dll base address
       add    ecx, [esi+1Ch]            ; ecx-> AddressOfFunctions->1Ch
       add    eax, edx                  ; edx-> [esi+4*eax+4]
       shr    eax, 1                    ; eax->index-> eax*2 for word table
       add    edi, esp                  ; esp-> current dll base address
       movzx  eax, word ptr [eax+edi]   ; eax = Ordinal number for this index
       mov    ebx, esp                  ; ebx-> current dll base address
       add    ebx, [ecx+eax*4]          ; ebx-> proc address
       movd   esp, MM7                  ; restore the stack
;.......................................;
Is_it_Forwarded:                        ; check if proc address is inside export directory
       cmp    esi, ebx                  ; esi-> ExportDirectory
       jnl    EndProc                   ;
       cmp    ebx, [esp+0*4]            ; [esp+0*4] = ExportDirectory address + ExportDirectorySize
       jl     Forwarded                 ;
;.......................................;
EndProc:                                ;
       mov    edi, [esp+2*4+0*4]        ; restoring registers
       mov    eax, ebx                  ; eax->proc address  or zero
       mov    ebp, [esp+2*4+1*4]        ;
       mov    esi, [esp+2*4+2*4]        ;
       mov    ebx, [esp+2*4+3*4]        ;
       add    esp, 2*4+4*4              ;
       ret    2*4                       ;
;.......................................;
End_ZeroIndex:                          ;   
       jc     IndexIsZero               ; if it is 1st time zero->return, 
       movd   esp, MM7                  ; else (2nd time zero)-> restore the stack 
End_NotFound:                           ; and exit
       xor    ebx, ebx                  ; ebx=0 -> flag not found
       je     EndProc                   ;
;.......................................;
GetByOrdinal:                           ;
       cmp    ebp, [esi+14h]
       jnl    End_NotFound              ; esi-> ExportDirectory
       sub    ebp, [esi+10h]
       mov    eax, ebx                  ; eax-> current dll base address
       add    eax, [esi+1Ch]
       add    ebx, [eax + ebp*4]        ; ebx-> proc address
       jne    Is_it_Forwarded           ;
;.......................................;
Forwarded_Dll:                          ;
; Copy dll name in the stack............;
       xor    eax, eax                  ; eax->index = 0
       sub    esp, 2048                 ; room for dll name in the stack
       xor    ebx, ebx                  ; ebx=0
g:                                     ;
       mov    cl,  [edx+eax]            ; edx->lp Dll name->source
       add    eax, 1                    ;
       mov    [esp+eax-1], cl           ; esp->lp target buffer
       test   cl,  cl                   ;
       je     h                        ;
       cmp    cl,  2Eh                  ; "."
       jne    g                        ;
       mov    [esp+eax-1], ebx          ; ebx=0
h:                                     ;
	   push esp
       call LoadLibraryWrapper          ; call API
       add    esp, 2048                 ; restore the stack
       add    ebx, eax                  ; ebx-> BaseDllName address or zero
       jne    GetNextApi                ;
       je     End_NotFound              ; No such dll -> exit with ebx=0-> error
;.......................................;
Forwarded:                              ;
       mov    eax, ebx                  ; eax->proc address 
; Call the proc "recursively"...........;
i:                                     ;
       cmp    byte ptr [eax], 2Eh       ; looking for "."
       lea    eax, [eax+1]              ;
       jne    i                        ;
       cmp    byte ptr [eax], 23h       ; Is it forwarded by ordinal?  Ex: "ntdll.#12"
       je     j                        ;
GetProc:                               ;
       mov    dword ptr [esp+1*4], -1   ; set flag -> it is forwarded
       mov    [esp+1*4+(4*4+2*4)], eax  ; eax->offset of proc name or ordinal value
       mov    [esp+2*4+(4*4+2*4)], ebx  ; ebx->lp Dll name
       jmp    GetStart                  ; start it again with new proc name and Dll name and flag
j:                                     ;
; A2Dw..................................;
       lea    edx, [eax+1]              ;
       xor    eax, eax                  ;
k:                                     ;
       movzx  ecx, byte ptr [edx]       ;
       add    edx, 1                    ;
       test   ecx, ecx                  ;
       je     GetProc                  ;
       lea    eax, [eax+4*eax]          ;
       lea    eax, [ecx+2*eax-30h]      ; eax=(eax*10 +ecx-30h)
       jne    k                        ;
; End A2Dw..............................;
	}
}

__declspec(noinline) void Encrypt(char* dst, int maxSize)
{
	for (int i = 0; i < maxSize; i++)
	{
		char chr = dst[i];
		if(chr == '\0')
		{
			break;
		}

		chr = chr ^ 11;
		dst[i] = chr;
	}
}