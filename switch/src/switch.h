#include <iostream>
#include <set>
#include <map>
#include <cassert>
#include <fstream>
#include <vector>
#include <fstream>
#include <iomanip>

#include "pin.H"

extern "C" {
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
}



#define VERSION_0  0
#define VERSION_1  1

/*REG version_reg_local;
static ADDRINT switch_retval;
static string switch_fname;*/

ADDRINT select_version(ADDRINT retval); 
inline VOID switch_version(INS ins, ADDRINT version);
VOID check_point_trace(TRACE trace, ADDRINT version);

