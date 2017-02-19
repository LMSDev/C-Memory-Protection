#include <Windows.h>
#include <winternl.h>
#include "VirtualMachine.h"
#include "macros.h"

inline PEB* GetPEB();

VirtualMachine::VirtualMachine(void)
{
	float useless = 54309543.f * 645645.f;
	if (3 == 3 && 54309543.f == 54309543.f && useless == 54309543.f * 645645.f)
	{
		// Force loading kernel32
		Beep(0, 0);
		VirtualMachine::nextInstructionAlign = 0;
		VirtualMachine::callTargetAlign = 0;
		VirtualMachine::instructionDataOffset = 0;
		VirtualMachine::globalsOffsetAlign = 0;
		VirtualMachine::stack = (int*)malloc(10 * 4); // Limited to 10 items
		VirtualMachine::stackCount = 0;
		VirtualMachine::tempValue = 0;
	}
}


VirtualMachine::~VirtualMachine(void)
{
}

void VirtualMachine::Initialize(void* instructionData, int size)
{
	// Initialize array
	for (int i = 0; i < 255; i++)
	{
		VirtualMachine::globalsPtr[i] = 0x0;
	}

#ifdef OBFUSCATE
	_asm
	{
		MOV		ebx, DWORD PTR FS:[18h]
		ADD		ebx, 10h // === Useless; add 10h to TEB
		MOV ebx, DWORD PTR DS:[ebx+20h] // === PEB; would be MOV EAX, DWORD PTR DS:[EAX+30] if we hadn't already added 10
		MOVZX ebx, BYTE PTR DS:[ebx+2] 
		test	ebx, ebx
		jz		NoDebugger
	}
	return;
#elif !OBFUSCATE
		PEB* peb = GetPEB();
		peb->BeingDebugged = 0;
#endif

NoDebugger:
	// Copy data
	VirtualMachine::instructionData = malloc(size);
	memcpy(VirtualMachine::instructionData, instructionData, size);
}

bool VirtualMachine::Run()
{
	// Fetch next instruction
	Instruction* nextInstruction = GetNextInstruction();

	// Note: This is used to change the actual instruction by the function used before, be careful when using this
	int nextInstructionCode = nextInstruction->code + VirtualMachine::nextInstructionAlign;

	// Execute
	switch (nextInstructionCode)
	{
		// CALL
	case -0x1:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];
			int function = globals[targetNumber + VirtualMachine::callTargetAlign];

			// Validate call
			int* memory = (int*)malloc(nextInstruction->callContext.functionSize);
			memcpy(memory, (void*)function, nextInstruction->callContext.functionSize);

			// If call starts with JUMP (E9), trace
			if (*(BYTE*)function == 0xE9)
			{
				DWORD jumpTarget = *(DWORD*)(function + 1);
				DWORD address = function;
				jumpTarget = address + jumpTarget + 5; // Calculate target by using the current address + the offset + 5 to skip the jump instruction

				memcpy(memory, (void*)jumpTarget, nextInstruction->callContext.functionSize);
			}

			// cout << "Hashing " << nextInstruction->callContext.hash << endl;

			// Hash memory
			int hash = 0;
			for (int i = 0; i < nextInstruction->callContext.functionSize; i++)
			{
				// cout << (BYTE)(memory)[i] << " ";
				hash += (BYTE)(memory)[i];
			}
			// cout << endl;
			if (hash < 0)
			{
				hash *= -1;
			}

			// cout << hash << " (" << nextInstruction->callContext.functionSize << ")" << endl;

			if (hash == nextInstruction->callContext.hash)
			{
				// cout << "Calling" << endl;
				void (*funcPtr)(CallContext callContext) = (void (*)(CallContext callContext))function;
				funcPtr(nextInstruction->callContext);
			}
			else
			{
				// cout << "Call surpressed" << endl;
			}
			// cin.get();
			//else
			//{
			//	MessageBoxA(0, "Illegally modified function detected", "Error", 0);
			//}

			// Free temp memory
			free(memory);
		}
		break;

		// LABEL
	case -0x2:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];

			// Get current offset (+ 4 to skip the parameter)
			instructionDataOffset += 4;
			int offset = instructionDataOffset;

			// Save offset
			globals[targetNumber] = offset;
		}
		break;

		// JMP
	case -0x3:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];
			instructionDataOffset = globals[targetNumber];
		}
		break;

		// STORE
	case -0x4:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];
			globals[targetNumber] = nextInstruction->callContext.arguments[1];

			instructionDataOffset += 8;
		}

		break;
	
		// CALLS
	case -0x5:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];
			int function = globals[targetNumber + VirtualMachine::callTargetAlign];

			// Validate call
			void* memory = malloc(nextInstruction->callContext.functionSize);
			memcpy(memory, (void*)function, nextInstruction->callContext.functionSize);

			// Hash memory
			int hash = nextInstruction->callContext.hash;

			if (hash == nextInstruction->callContext.hash)
			{
				// Append stack to arguments (4 = first argument (the target number) + all arguments on the stack * 4)
				void* tempMemory = malloc(4 + VirtualMachine::stackCount * 4);
				memcpy(tempMemory, nextInstruction->callContext.arguments, 4);
				memcpy((void*)((int)tempMemory + 0x4), VirtualMachine::stack, VirtualMachine::stackCount * 4);

				// Free old arguments
				free(nextInstruction->callContext.arguments);

				// Store new
				nextInstruction->callContext.arguments = (int*)tempMemory;
				VirtualMachine::stackCount = 0;

				// Call function
				void (*funcPtr)(CallContext callContext) = (void (*)(CallContext callContext))function;
				funcPtr(nextInstruction->callContext);

				// Targets called using stack don't have their arguments in the raw byte data, so we only have to skip 4 bytes everytime
				instructionDataOffset += 4;
			}

			// Free temp memory
			free(memory);
		}
		break;

		// PUSH
	case -0x6:
		{
			VirtualMachine::stack[VirtualMachine::stackCount] = VirtualMachine::tempValue;
			VirtualMachine::stackCount++;
		}

		break;

		// LOAD
	case -0x7:
		{
			// Decode target
			int* globals = VirtualMachine::globalsPtr[nextInstruction->callContext.globals + VirtualMachine::globalsOffsetAlign];
			VirtualMachine::globalsOffsetAlign = 0;
			int targetNumber = nextInstruction->callContext.arguments[0];
			VirtualMachine::tempValue = globals[targetNumber];

			instructionDataOffset += 4;
		}

		break;

		// INT3
	case -0x8:
		_asm INT 3
		break;

	}

	// Free arguments
	free(nextInstruction->callContext.arguments);

	// Discard instruction
	delete nextInstruction;
	nextInstruction = NULL;

	return nextInstructionCode != -0xDEAD;
}

void VirtualMachine::Shutdown()
{
	free(VirtualMachine::stack);
	free(VirtualMachine::instructionData);
}

void* VirtualMachine::GetDataStream()
{
	return VirtualMachine::instructionData;
}

void VirtualMachine::AddGlobals(int* globals)
{
	for (int i = 0; i < 255; i++)
	{
		if (VirtualMachine::globalsPtr[i] == 0x0)
		{
			VirtualMachine::globalsPtr[i] = globals;
			break;
		}
	}
}

Instruction* VirtualMachine::GetNextInstruction()
{
	// Allocate 4 bytes for the code (integer)
	void* instructionCode = malloc(4);
	int firstInstruction = 0;
#ifdef OBFUSCATE
	int address = (int)VirtualMachine::instructionData + VirtualMachine::instructionDataOffset + GetPEB()->BeingDebugged;
#elif !OBFUSCATE
	int address = (int)VirtualMachine::instructionData + VirtualMachine::instructionDataOffset;
#endif
	int timesRead = 0;

	// Read until negative code (so an instruction) is present a second time
	while (true)
	{
		memcpy(instructionCode, (void*)(address + timesRead * 4), sizeof(instructionCode));
		int code = *(int*)instructionCode;

#ifdef OBFUSCATE
#ifndef _DEBUG
		bool (VirtualMachine::*funcPtr)(void) = &VirtualMachine::IsDbgPresentPrefixCheck;
		BYTE pPtr = *((BYTE*&)funcPtr);
		if (pPtr != 0x55)
		{
			*(int*)instructionCode = *(int*)instructionCode - 1;
		}
#endif
#endif

		// If code below 0, so an instruction
		if (code < 0)
		{
			// If first time, store instruction
			if (timesRead == 0)
			{
				firstInstruction = *(int*)instructionCode;
			}
			else
			{
				// If not the first time, we have reached another instruction, so we abort
				if (timesRead > 0)
				{
					break;
				}
			}
		}

		// If end of stream, abort
		if (code == -0xDEAD)
		{
			break;
		}

		timesRead++;
	}

	// Adjust offset for the next time, however we don't take the arguments into account but the fixed size of 6 for the context (5) and instruction (1)
	// The offset for the arguments has to be adjusted by the called function
	VirtualMachine::instructionDataOffset += 24;

	// Build instruction
	Instruction* instruction = new Instruction();
	instruction->code = firstInstruction;
	int paramCount = timesRead - 6;
	if (paramCount < 0) paramCount = 0;

	// Subtract 24 to get rid of recently added offset
#ifdef OBFUSCATE
		address = (int)VirtualMachine::instructionData + VirtualMachine::instructionDataOffset + VirtualMachine::IsDbgPresentPrefixCheck() + 4 - 24;
#elif !OBFUSCATE
		address = (int)VirtualMachine::instructionData + VirtualMachine::instructionDataOffset + 4 - 24;
#endif
	memcpy(&instruction->callContext.hash, (void*)address, 4);
	memcpy(&instruction->callContext.functionSize, (void*)(address + 4), 4);
	memcpy(&instruction->callContext.storedBytes, (void*)(address + 8), sizeof(instruction->callContext.storedBytes));
	memcpy(&instruction->callContext.bytesOffset, (void*)(address + 8 + sizeof(instruction->callContext.storedBytes)), 4);
	memcpy(&instruction->callContext.globals, (void*)(address + 12 + sizeof(instruction->callContext.storedBytes)), 4);
	instruction->callContext.arguments = (int*)malloc(paramCount * 4);
	memcpy(instruction->callContext.arguments, (void*)(address + 16 + sizeof(instruction->callContext.storedBytes)), paramCount * 4);

	free(instructionCode);
	return instruction;
}

void VirtualMachine::AdjustDataOffset(int offset)
{
	VirtualMachine::instructionDataOffset += offset;
}

void VirtualMachine::AdjustInstructionCode(int offset)
{
	VirtualMachine::nextInstructionAlign += offset;
}

void VirtualMachine::AdjustCallTarget(int offset)
{
	VirtualMachine::callTargetAlign += offset;
}

void VirtualMachine::AdjustGlobalsOffset(int offset)
{
	VirtualMachine::globalsOffsetAlign += offset;
}

inline PEB* GetPEB()
{
__asm
	{
		mov EAX, fs:30h
	}
}

// The IsDbgPresentPrefixCheck works in at least two debuggers
// OllyDBG and VS 2008, by utilizing the way the debuggers handle
// prefixes we can determine their presence. Specifically if this code
// is ran under a debugger it will simply be stepped over;
// however, if there is no debugger SEH will fire :D
__forceinline bool VirtualMachine::IsDbgPresentPrefixCheck()
{
    __try
    {
        __asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
        __asm __emit 0x64
        __asm __emit 0xF1 // One byte INT 1
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    return true;
}