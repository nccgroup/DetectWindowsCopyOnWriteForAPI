// Includes
#include "stdafx.h"
#include "Engine.h"

bool	bService = false;
bool	bConsole = false;

// Globals
HANDLE	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

/// 
int _tmain(int argc, _TCHAR* argv[])
{
	fwprintf(stdout, _TEXT("[i] Running..\n"));
	EnumerateProcesses();

	return 0;
}