/*
Enmumerate ALPC call backs

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

Released under AGPL see LICENSE for more information
*/

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