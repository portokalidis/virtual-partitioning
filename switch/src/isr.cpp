
#include <pin.H>


#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <cassert>
#include <set>
#include <list>

#include "log.hpp"
#include "libisr.hpp"
#include "watchdog.hpp"

extern "C" {
#include <link.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sqlite3.h>
#include <err.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
}

#define DTA
#include "switch.h"

/*this required for libdft*/

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"


#define SUCCESS_MSG "<minestrone>EXIT_SUCCESS</minestrone>\n"
#define TIMEOUT_OPTION "timeout"


using namespace std;

// Original name
static KNOB<string> KnobOriginalName(KNOB_MODE_WRITEONCE, "pintool",
    "n", "", "Specify executable's original name, for logging purposes.");
// Image keys DB
static KNOB<string> KnobKeyDB(KNOB_MODE_WRITEONCE, "pintool", "keydb", "",
		 "Key database to use");
// Timeout in seconds (we exit if execution takes more than this value)
static KNOB<unsigned long long> KnobTimeout(KNOB_MODE_WRITEONCE, "pintool", 
		TIMEOUT_OPTION, "0", "Timeout in seconds. Stop executing "
		"after specified amount of seconds). 0 disables timeout.");


// Watchdog stuff

// For correct watchdog support for children
static struct command_line {
        int argc;
        char **argv;
} cmdln;

static VOID Fork(THREADID tid, const CONTEXT *ctx, VOID *v)
{
	// Start watchdog for new process, if necessary
	if (KnobTimeout.Value() > 0) {
		if (!WatchdogStart())
			PIN_ExitApplication(EXIT_FAILURE);
	}
}

static BOOL ChildExec(CHILD_PROCESS child, VOID *v)
{
	int i;
	CHAR timeout[128];

	if (KnobTimeout.Value() == 0)
		return TRUE;

	for (i = 0; i < cmdln.argc; i++) {
		// Stop looking if we reached the application's arguments
		if (strcmp(cmdln.argv[i], "--") == 0)
			break;
		// Look for the timeout option
		if (strcmp(cmdln.argv[i], "-"TIMEOUT_OPTION) == 0) {
			if (++i >= cmdln.argc) {
				ERRLOG("No timeout option found in exec'ed "
						"child's command line\n");
				PIN_ExitApplication(EXIT_FAILURE);
			}
			snprintf(timeout, sizeof(timeout), "%llu", 
					WatchdogRemaining());
			cmdln.argv[i] = timeout;
			break;
		} 
	}

	CHILD_PROCESS_SetPinCommandLine(child, cmdln.argc, cmdln.argv);
	return TRUE;
}

// Make a copy of the command line arguments
static VOID SaveCmdLine(int argc, char **argv)
{
	int i;
	char *argv_copy;

	cmdln.argc = argc;
	cmdln.argv = (char **)malloc((argc + 1) * sizeof(char **));
	assert(cmdln.argv);

	for (i = 0; i < argc; i++) {
		argv_copy = strdup(argv[i]);
		assert(argv_copy);
		//cout << "ARG[" << i << "]=" << argv_copy << endl;
		cmdln.argv[i] = argv_copy;
	}
	cmdln.argv[i] = NULL;
}

static VOID LogEvent(BOOL ci)
{
	stringstream sstr;

	/* Only produce minestrone style messages if the name of the binary is
	 * specified */
	if (KnobOriginalName.Value().empty())
		return;

	if (ci) {
		sstr << "<structured_message>" << endl;
		sstr << "\t<message_type>found_cwe</message_type>" << endl;
		// CWE-94 Failure to Control Generation of Code 
		// ('Code Injection')
		sstr << "\t<cwe_entry_id>94</cwe_entry_id>" << endl;
		sstr << "</structured_message>" << endl;
		NOTIFY(sstr);
	}

	sstr << "<structured_message>" << endl;
	sstr << "\t<message_type>controlled_exit" << 
		"</message_type>" << endl;
	sstr << "\t<test_case>" << KnobOriginalName.Value() << 
		"</test_case>" << endl;
	sstr << "</structured_message>" << endl;

	sstr << "<structured_message>" << endl;
	sstr << "\t<message_type>technical_impact" << 
		"</message_type>" << endl;
	sstr << "\t<impact>";
	if (ci)
		sstr << "EXECUTE_UNAUTHORIZED_CODE";
	else
		sstr << "DOS_INSTABILITY";
	sstr << "</impact>" << endl;
	sstr << "\t<test_case>" << KnobOriginalName.Value() << 
		"</test_case>" << endl;
	sstr << "</structured_message>" << endl;
	NOTIFY(sstr);
}

static BOOL FaultHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	string exceptname;
	stringstream sstr;
	ADDRINT feip;
	BOOL code_injection;
	unsigned char tmpbuf[1];
	
	exceptname = PIN_ExceptionToString(pExceptInfo);
	feip = PIN_GetExceptionAddress(pExceptInfo);
	if (feip == 0) {
		feip = PIN_GetContextReg(ctx, REG_INST_PTR);
	}

	sstr << "ISRUPIN thread [" << tid << "] fault at " << 
		(void *)feip << endl << exceptname << endl;
	NOTIFY(sstr);

	code_injection = FALSE;
	// We are trying to execute unknown code, from a memory
	// accessible area --> code-injection
	if (!libisr_known_image(feip) &&
			PIN_SafeCopy(tmpbuf, (VOID *)feip, 1) == 1) {
		/* It's a CI if we are executing from an accessible, but unknown
		 * image */
		code_injection = TRUE;
		NOTIFY("!!!Code-injection detected!!!\n");
	}
	LogEvent(code_injection);

	if (code_injection)
		PIN_ExitApplication(EXIT_FAILURE);
	return TRUE;
}



static VOID Fini(INT32 code, VOID *v)
{
	NOTIFY(SUCCESS_MSG);
}

static VOID Usage(void)
{
        cerr << "This is the ISR Pin tool." << endl;
        cerr << KNOB_BASE::StringKnobSummary() << endl;
}

#ifdef DTA
#define WORD_LEN	4	/* size in bytes of a word value */
#define SYS_SOCKET	1	/* socket(2) demux index for socketcall */
				/* default path for the log file (audit) */
#define LOGFILE_DFL	"/tmp/libdft-dta.log"


/* thread context */
extern REG thread_ctx_ptr;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

/* log file path (auditing) */
KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "i", LOGFILE_DFL, "");

/* 
 * DTA/DFT alert
 *
 * @ins:	address of the offending instruction
 * @bt:		address of the branch target
 */
static void PIN_FAST_ANALYSIS_CALL
alert(ADDRINT ins, ADDRINT bt)
{
	/* log file */
	FILE *logfile;

	/* auditing */
	if (likely((logfile = fopen(logpath.Value().c_str(), "a")) != NULL)) {
		/* hilarious :) */
		(void)fprintf(logfile, " ____ ____ ____ ____\n");
		(void)fprintf(logfile, "||w |||o |||o |||t ||\n");
		(void)fprintf(logfile, "||__|||__|||__|||__||\t");
		(void)fprintf(logfile, "[%d]: 0x%08x --> 0x%08x\n",
							getpid(), ins, bt);

		(void)fprintf(logfile, "|/__\\|/__\\|/__\\|/__\\|\n");
		
		/* cleanup */
		(void)fclose(logfile);
	}
	else
		/* failed */
		warnx("%s:%u: failed while trying to open the log(%s)",
				__func__, __LINE__, logpath.Value().c_str());

	/* terminate */
	exit(EXIT_FAILURE);
}

/*
 * 32-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg32(thread_ctx_t *thread_ctx, uint32_t reg)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return thread_ctx->vcpu.gpr[reg];
}

/*
 * 16-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg16(thread_ctx_t *thread_ctx, uint32_t reg)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return (thread_ctx->vcpu.gpr[reg] & VCPU_MASK16);
}

/*
 * 32-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem32(ADDRINT paddr)
{
	return tagmap_getl(paddr);
}

/*
 * 16-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem16(ADDRINT paddr)
{
	return tagmap_getw(paddr);
}

/*
 * instrument the jmp/call instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg),
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg),
					IARG_END);
		}
		else {
		/* call via memory */
			/* size analysis */
				
			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_END);
		}
		/*
		 * instrument alert() before branch;
		 * conditional instrumentation -- then
		 */
		INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(alert),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}

/*
 * instrument the conditional jmp instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
#if 0
static void
dta_instrument_cjmp(INS ins)
{
	/* temporaries */
	REG reg;

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before cjmp;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg),
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before cjmp;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg),
					IARG_END);
		}
		else {
		/* call via memory */
			/* operand analysis */

			/* size analysis */
				
			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before cjmp;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before cjmp;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_END);
		}
		/*
		 * instrument alert() before cjmp;
		 * conditional instrumentation -- then predicated
		 */
		INS_InsertThenPredicatedCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(alert),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}
#endif

/*
 * instrument the ret instruction
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_ret(INS ins)
{
	/* size analysis */
				
	/* 32-bit */
	if (INS_MemoryReadSize(ins) == WORD_LEN)
		/*
		 * instrument assert_mem32() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(assert_mem32),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_END);
	/* 16-bit */
	else
		/*
		 * instrument assert_mem16() before ret;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(assert_mem16),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_END);
	
	/*
	 * instrument alert() before ret;
	 * conditional instrumentation -- then
	 */
	INS_InsertThenCall(ins,
		IPOINT_BEFORE,
		AFUNPTR(alert),
		IARG_FAST_ANALYSIS_CALL,
		IARG_INST_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_END);
}

/*
 * read(2) handler (taint-source)
 */
static void
post_read_hook(syscall_ctx_t *ctx)
{
        /* read() was not successful; optimized branch */
        if (unlikely((long)ctx->ret <= 0))
                return;
	
	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        	/* set the tag markings */
	        tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
	else
        	/* clear the tag markings */
	        tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/*
 * readv(2) handler (taint-source)
 */
static void
post_readv_hook(syscall_ctx_t *ctx)
{
	/* iterators */
	int i;
	struct iovec *iov;
	set<int>::iterator it;

	/* bytes copied in a iovec structure */
	size_t iov_tot;

	/* total bytes copied */
	size_t tot = (size_t)ctx->ret;

	/* readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
			(size_t)iov->iov_len : tot;
	
		/* taint interesting data and zero everything else */	
		if (it != fdset.end())
                	/* set the tag markings */
                	tagmap_setn((size_t)iov->iov_base, iov_tot);
		else
                	/* clear the tag markings */
                	tagmap_clrn((size_t)iov->iov_base, iov_tot);

                /* housekeeping */
                tot -= iov_tot;
        }
}

/*
 * socketcall(2) handler
 *
 * attach taint-sources in the following
 * syscalls:
 * 	socket(2), accept(2), recv(2),
 * 	recvfrom(2), recvmsg(2)
 *
 * everything else is left intact in order
 * to avoid taint-leaks
 */
static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
	/* message header; recvmsg(2) */
	struct msghdr *msg;

	/* iov bytes copied; recvmsg(2) */
	size_t iov_tot;

	/* iterators */
	size_t i;
	struct iovec *iov;
	set<int>::iterator it;
	
	/* total bytes received */
	size_t tot;
	
	/* socket call arguments */
	unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

	/* demultiplex the socketcall */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case SYS_SOCKET:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;

			/*
			 * PF_INET and PF_INET6 descriptors are
			 * considered interesting
			 */
			if (likely(args[SYSCALL_ARG0] == PF_INET ||
				args[SYSCALL_ARG0] == PF_INET6))
				/* add the descriptor to the monitored set */
				fdset.insert((int)ctx->ret);

			/* done */
			break;
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
			/*
			 * if the socket argument is interesting,
			 * the returned handle of accept(2) is also
			 * interesting
			 */
			if (likely(fdset.find(args[SYSCALL_ARG0]) !=
						fdset.end()))
				/* add the descriptor to the monitored set */
				fdset.insert((int)ctx->ret);
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;

			/* addr argument is provided */
			if ((void *)args[SYSCALL_ARG1] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG1],
					*((int *)args[SYSCALL_ARG2]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG2], sizeof(int));
			}
			break;
		case SYS_SOCKETPAIR:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3], (sizeof(int) * 2));
			break;
		case SYS_RECV:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
			
			/* taint-source */	
			if (fdset.find((int)args[SYSCALL_ARG0]) != fdset.end())
				/* set the tag markings */
				tagmap_setn(args[SYSCALL_ARG1],
							(size_t)ctx->ret);
			else
				/* clear the tag markings */
				tagmap_clrn(args[SYSCALL_ARG1],
							(size_t)ctx->ret);
			break;
		case SYS_RECVFROM:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
	
			/* taint-source */	
			if (fdset.find((int)args[SYSCALL_ARG0]) != fdset.end())
				/* set the tag markings */
				tagmap_setn(args[SYSCALL_ARG1],
						(size_t)ctx->ret);
			else
				/* clear the tag markings */
				tagmap_clrn(args[SYSCALL_ARG1],
						(size_t)ctx->ret);

			/* sockaddr argument is specified */
			if ((void *)args[SYSCALL_ARG4] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG4],
					*((int *)args[SYSCALL_ARG5]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG5], sizeof(int));
			}
			break;
		case SYS_GETSOCKOPT:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3],
					*((int *)args[SYSCALL_ARG4]));
			
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG4], sizeof(int));
			break;
		case SYS_RECVMSG:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
			
			/* get the descriptor */
			it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

			/* extract the message header */
			msg = (struct msghdr *)args[SYSCALL_ARG1];

			/* source address specified */
			if (msg->msg_name != NULL) {
				/* clear the tag bits */
				tagmap_clrn((size_t)msg->msg_name,
					msg->msg_namelen);
				
				/* clear the tag bits */
				tagmap_clrn((size_t)&msg->msg_namelen,
						sizeof(int));
			}
			
			/* ancillary data specified */
			if (msg->msg_control != NULL) {
				/* taint-source */
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)msg->msg_control,
						msg->msg_controllen);
					
				else
					/* clear the tag markings */
					tagmap_clrn((size_t)msg->msg_control,
						msg->msg_controllen);
					
				/* clear the tag bits */
				tagmap_clrn((size_t)&msg->msg_controllen,
						sizeof(int));
			}
			
			/* flags; clear the tag bits */
			tagmap_clrn((size_t)&msg->msg_flags, sizeof(int));	
			
			/* total bytes received */	
			tot = (size_t)ctx->ret;

			/* iterate the iovec structures */
			for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
				/* get the next I/O vector */
				iov = &msg->msg_iov[i];

				/* get the length of the iovec */
				iov_tot = (tot > (size_t)iov->iov_len) ?
						(size_t)iov->iov_len : tot;
				
				/* taint-source */	
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)iov->iov_base,
								iov_tot);
				else
					/* clear the tag markings */
					tagmap_clrn((size_t)iov->iov_base,
								iov_tot);
		
				/* housekeeping */
				tot -= iov_tot;
			}
			break;
#if LINUX_KERNEL >= 2633
		case SYS_RECVMMSG:
#endif
		default:
			/* nothing to do */
			return;
	}
}

/*
 * auxiliary (helper) function
 *
 * duplicated descriptors are added into
 * the monitored set
 */
static void
post_dup_hook(syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the old descriptor argument is
	 * interesting, the returned handle is
	 * also interesting
	 */
	if (likely(fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end()))
		fdset.insert((int)ctx->ret);
}

/*
 * auxiliary (helper) function
 *
 * whenever close(2) is invoked, check
 * the descriptor and remove if it was
 * inside the monitored set of descriptors
 */
static void
post_close_hook(syscall_ctx_t *ctx)
{
	/* iterator */
	set<int>::iterator it;

	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the descriptor (argument) is
	 * interesting, remove it from the
	 * monitored set
	 */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);
	if (likely(it != fdset.end()))
		fdset.erase(it);
}

/* 
 * DTA
 *
 * used for demonstrating how to implement
 * a practical dynamic taint analysis (DTA)
 * tool using libdft
 */ 
#endif

ADDRINT switch_retval;
string switch_fname;


static KNOB<string> FunctionName(KNOB_MODE_WRITEONCE, "pintool", "f",
		                "", "Name of authenticaiton function.");

static KNOB<ADDRINT> FunctionRet(KNOB_MODE_WRITEONCE, "pintool", "r",
		                "0", "Return value that indicates successful authentication.");


int main(int argc, char **argv)
{
	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		return EXIT_FAILURE;
	}

	//	switch_fname = "hash_password_check";
	//switch_fname = "check_scramble";
//	switch_fname = "verify_pwd_hash";

 


        switch_fname = FunctionName.Value();
	if (switch_fname.empty()) {
		cerr << "Undefined function name" << endl;
	        return EXIT_FAILURE;
	}
    //    cerr << "Function name " << switch_fname << endl;
	
	switch_retval = FunctionRet.Value();
	//if(switch_retval.empty()){
	//	cerr << "Undefined return value" << endl;
	  //      return EXIT_FAILURE;
	//}
	//cerr << "Return value " << switch_retval << endl;


//	switch_fname = "pam_authenticate";
//       switch_retval = 0;

	// Initialize ISR library
	libisr_init(KnobKeyDB.Value().c_str());

#ifdef DTA
	if (unlikely(libdft_init(argc, argv) != 0))
		return 1;
#endif

	// Intercept signals that can received due to an attack 
	PIN_UnblockSignal(SIGSEGV, TRUE);
	PIN_InterceptSignal(SIGSEGV, FaultHandler, 0);
	PIN_UnblockSignal(SIGILL, TRUE);
	PIN_InterceptSignal(SIGILL, FaultHandler, 0);
	PIN_UnblockSignal(SIGABRT, TRUE);
	PIN_InterceptSignal(SIGABRT, FaultHandler, 0);
	PIN_UnblockSignal(SIGFPE, TRUE);
	PIN_InterceptSignal(SIGFPE, FaultHandler, 0);
	PIN_UnblockSignal(SIGBUS, TRUE);
	PIN_InterceptSignal(SIGBUS, FaultHandler, 0);
	PIN_UnblockSignal(SIGSYS, TRUE);
	PIN_InterceptSignal(SIGSYS, FaultHandler, 0);
	PIN_UnblockSignal(SIGTRAP, TRUE);
	PIN_InterceptSignal(SIGTRAP, FaultHandler, 0);

	// If a timeout has been specified, setup and start the watchdog
	if (KnobTimeout.Value() > 0) {
		SaveCmdLine(argc, argv);
		WatchdogInit(KnobTimeout.Value());
		PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, Fork, 0);
		PIN_AddFollowChildProcessFunction(ChildExec, NULL);
		if (!WatchdogStart())
			return EXIT_FAILURE;
	}

	if (!KnobOriginalName.Value().empty())
		PIN_AddFiniFunction(Fini, 0);

//////////////////////////////////////////////////
#ifdef DTA
	/* instrument call */
	(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
			dta_instrument_jmp_call);
	
	/* instrument jmp */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JMP],
			dta_instrument_jmp_call);

	/* instrument ret */
	(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR],
			dta_instrument_ret);

#if 0
	/* instrument conditional branches */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JB],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JBE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JL],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JLE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNB],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNBE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNL],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNLE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNO],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNP],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNS],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNZ],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JO],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JP],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JRCXZ],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JS],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JZ],
			dta_instrument_cjmp);
#endif

	/* 
	 * install taint-sources
	 *
	 * all network-related I/O calls are
	 * assumed to be taint-sources; we
	 * install the appropriate wrappers
	 * for tagging the received data
	 * accordingly -- Again, for brevity
	 * I assume that all calls to
	 * syscall_set_post() are successful
	 */
	
	/* read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	/* readv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);

	/* socket(2), accept(2), recv(2), recvfrom(2), recvmsg(2) */
	(void)syscall_set_post(&syscall_desc[__NR_socketcall],
			post_socketcall_hook);

	/* dup(2), dup2(2) */
	(void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);

	/* close(2) */
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);

	/* start execution */
	libdft_start();
 
#endif

	// Start the program, never returns
//	PIN_StartProgram();

	// Cleanup ISR library
	libisr_cleanup();

	return EXIT_SUCCESS;
}
