#pragma once

struct CallContext
{
	int hash;
	int functionSize;
	int storedBytes[1];
	int bytesOffset;
	int globals;
	int* arguments; 
};

struct Instruction
{
	int code;
	CallContext callContext;
};

class VirtualMachine
{
public:
	VirtualMachine(void);
	~VirtualMachine(void);

	void Initialize(void* instructionData, int size);
	bool Run();
	void Shutdown();
	void* GetDataStream();
	void AddGlobals(int* globals);
	void AdjustDataOffset(int offset);
	void AdjustInstructionCode(int offset);
	void AdjustCallTarget(int offset);
	void AdjustGlobalsOffset(int offset);
	bool IsDbgPresentPrefixCheck();

private:
	int nextInstructionAlign;
	int callTargetAlign;
	int globalsOffsetAlign;

	int* globalsPtr[255];
	void* instructionData;
	int instructionDataOffset;

	int* stack;
	int stackCount;
	int tempValue;

	Instruction* GetNextInstruction();
};