#include <iostream>
#include "pin.H"

extern "C" {
#include <stdlib.h>
#include <string.h>
}

#define WRAPPER_NAME "isr_wrapper.so"
#define ISR_NAME "isr.so"

//#define DEBUG

static struct command_line {
	int argc;
	char **argv;
} cmdln;


// Log file
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "isr.log", "Specify output file name. .PID is appended");

// Image keys DB
KNOB<string> KnobKeyDB(KNOB_MODE_WRITEONCE, "pintool", "keydb", "",
		"Key database to use");

KNOB<string> FunctionName(KNOB_MODE_WRITEONCE, "pintool", "n",
		                                "", "Name of authenticaiton function.");

KNOB<ADDRINT> FunctionRet(KNOB_MODE_WRITEONCE, "pintool", "r",
		                                "0", "Return value that indicates successful authentication.");



static BOOL ChildStarts(CHILD_PROCESS child, VOID *v)
{
	int i, j, tool_follows, wrapper_follows;
	char *tname;

#ifdef DEBUG
	cout << "exec() detected" << endl;
	cout << "command line arguments " << cmdln.argc << endl;
#endif
	tool_follows = wrapper_follows = 0;
	for (i = 0; i < cmdln.argc; i++) {
#ifdef DEBUG
		cout << "Child arg[" << i << "] = " << cmdln.argv[i] << endl;
#endif

		if (tool_follows) {
			tname = strstr(cmdln.argv[i], WRAPPER_NAME);
			tool_follows = 0;

			// Sanity check that we can modify the tool name in
			// place
			if (strlen(ISR_NAME) > strlen(WRAPPER_NAME)) {
				cerr << "Cannot modify tool name in place, "
					"ISR disabled" << endl;
				return FALSE;
			}

			if (tname)
				strcpy(tname, ISR_NAME);
			else {
				cerr << "Expected different tool name, correct "
					"WRAPPER_NAME definition" << endl;
				return FALSE;
			}
		} else if (wrapper_follows) {
			wrapper_follows = 0;

			for (j = i; j < cmdln.argc; j++)
				cmdln.argv[j] = cmdln.argv[j + 1];
			cmdln.argc--;
		}

		if (strcmp(cmdln.argv[i], "-t") == 0)
			tool_follows = 1;
		else if (strcmp(cmdln.argv[i], "--") == 0)
			wrapper_follows = 1;
	}

#ifdef DEBUG
	cout << "corrected command line" << endl;
	for (i = 0; i < cmdln.argc; i++) 
		cout << "Child arg[" << i << "] = " << cmdln.argv[i] << endl;
#endif

	CHILD_PROCESS_SetPinCommandLine(child, cmdln.argc, cmdln.argv);

	return TRUE;
}

static VOID Usage(void)
{
	cerr << "This is the ISR wrapper PIN tool, to be called with "
		"'exec_wrapper'. Executed children will be run with the "
		"proper ISR PIN tool." << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;

}



int main(int argc, char *argv[])
{
	int i;
	char *argv_copy;

	// Copy command line arguments
	cmdln.argc = argc;
	cmdln.argv = (char **)malloc((argc + 1) * sizeof(char **));
	if (!cmdln.argv) {
		cerr << "Not enough memory" << endl;
		return -1;
	}
	for (i = 0; i < argc; i++) {
		argv_copy = strdup(argv[i]);
		if (!argv_copy) {
			cerr << "Not enough memory" << endl;
			return -1;
		}
		//cout << "ARG[" << i << "]=" << argv_copy << endl;
		cmdln.argv[i] = argv_copy;
	}
	cmdln.argv[i] = NULL;

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		return -1;
	}

	// Capture the wrapper's exec()
	PIN_AddFollowChildProcessFunction(ChildStarts, &cmdln);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
