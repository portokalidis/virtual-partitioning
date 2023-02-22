#include <iostream>
//#include <fstream>

#include "pin.H"




static INT32 Usage()
{
	cerr << "This tool counts the number of dynamic instructions executed" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv))
		return Usage();

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
