/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in October 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * TODO:
 * 	- add support for file descriptor duplication via fcntl(2)
 * 	- add support for non PF_INET* sockets
 * 	- add support for recvmmsg(2)
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <cassert>

#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <set>

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"

#define WORD_LEN	4	/* size in bytes of a word value */
#define SYS_SOCKET	1	/* socket(2) demux index for socketcall */

/* Maximum length of path type spefication strings in fslist entries */
#define PATH_TYPE_MAX	10

/* This version always reverts to the active version */
#define AUTOCORRECT_VERSION	0
/* Default execution (no DTA) */
#define DEFAULT_VERSION		1
/* Execution using DTA */
#define DTA_VERSION		2


/* Enable debugging messages */
#define PARTITIONED_DTA_DEBUG

/* Pin scratch register for switching between execution versions */
static REG version_reg;

/* thread context */
extern REG thread_ctx_ptr;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

/* Set of tracked files */
static set<string> tracked_files;

/* Set of instructions following a system call */
static set<ADDRINT> postsyscall_ins;

/*
 * flag variables
 *
 * 0	: feature disabled
 * >= 1	: feature enabled
 */ 

/* issue an alert when tainted data is written to any fd (enabled by default) */
static KNOB<size_t> alertall(KNOB_MODE_WRITEONCE, "pintool", 
		"alert-all", "1", "");

/* use a list of files to track */
static KNOB<string> fslist(KNOB_MODE_WRITEONCE, "pintool", "fslist", "", "");

/* Enable partitioned DTA, use DTA only when a thread opens an 
 * interesting file */
static KNOB<bool> partitioned(KNOB_MODE_WRITEONCE, "pintool", "p", "1", "");


/* 
 * Data leakage alert
 */
static void 
alert(int fd, ADDRINT data_addr, size_t len)
{
	stringstream ss;

	ss << "ALERT: sensitive data being written to fd:" << fd << endl;
	LOG(ss.str());
}

/*
 * read(2) and pread(2) handler (taint-source)
 */
static void
post_read_hook(syscall_ctx_t *ctx)
{
        /* read() was not successful; optimized branch */
        if (unlikely((long)ctx->ret <= 0))
                return;
	
	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end()) {
#ifdef PARTITIONED_DTA_DEBUG
		stringstream ss;
		ss << "Tainting data from fd:" << 
			ctx->arg[SYSCALL_ARG0] << endl;
		LOG(ss.str());
#endif
        	/* set the tag markings */
	        tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

		if (partitioned.Value()) {
			/* Switch instrumentation version */
			PIN_SetContextReg((CONTEXT *)ctx->aux, 
					version_reg, DTA_VERSION);
		}
	} else
        	/* clear the tag markings */
	        tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/*
 * write(2) handler (taint-sink)
 */
static void
pre_write_hook(syscall_ctx_t *ctx)
{
	size_t len;
	ADDRINT buf_addr;

	buf_addr = ctx->arg[SYSCALL_ARG1];
	len = ctx->arg[SYSCALL_ARG2];

	/* Sanity check, make sure we wont overflow the tagmap */
	if ((~0UL - buf_addr) < len)
		return;

	//cout << "Checking data written to fd:" << ctx->arg[SYSCALL_ARG0] << endl;

	/* check tagmap */
	if (tagmap_issetn(buf_addr, len) != 0) {
		stringstream ss;
		ss << "Something was tainted in " << (void *)buf_addr << '-' <<
			(void *)(buf_addr + len) << endl;
		alert(ctx->arg[SYSCALL_ARG0], buf_addr, len);
	}
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
		if (it != fdset.end()) {
                	/* set the tag markings */
                	tagmap_setn((size_t)iov->iov_base, iov_tot);

			if (partitioned.Value()) {
				/* Switch instrumentation version */
				PIN_SetContextReg((CONTEXT *)ctx->aux, 
						version_reg, DTA_VERSION);
			}
		} else
                	/* clear the tag markings */
                	tagmap_clrn((size_t)iov->iov_base, iov_tot);

                /* housekeeping */
                tot -= iov_tot;
        }
}

#if 0
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
#endif

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

static bool
fslist_check_fd(int fd)
{
	int l;
	char pathname[80], realfn[PATH_MAX];
	set<string>::iterator res;

	snprintf(pathname, sizeof(pathname), "/proc/%d/fd/%d", PIN_GetPid(), fd);


	/* Get the original filename. It can fail if fd is a socket or pipe */
	if ((l = readlink(pathname, realfn, sizeof(realfn))) < 0)
		return false;
	realfn[l] = '\0';

#ifdef PARTITIONED_DTA_DEBUG
	stringstream ss;
	ss << fd << " = open() --> " << realfn << endl;
	LOG(ss.str());
#endif

	res = tracked_files.find(realfn);
	if (res != tracked_files.end()) {
#ifdef PARTITIONED_DTA_DEBUG
		LOG("INTERESTING FILE\n");
#endif
		return true;
	}

	return false;
}

/*
 * auxiliary (helper) function
 *
 * whenever open(2)/creat(2) is invoked,
 * add the descriptor inside the monitored
 * set of descriptors
 *
 * NOTE: it does not track dynamic shared
 * libraries
 */
static void
post_open_hook(syscall_ctx_t *ctx)
{
	bool interesting = false;

	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	if (!fslist.Value().empty()) {
		/* Check if file is in the list and should be tracked */
		//interesting = fslist_check_fn(ctx->arg[SYSCALL_ARG0]);
		interesting = fslist_check_fd((int)ctx->ret);
	}

	if (interesting) {
		/* Add fd to interesting descriptors */
		fdset.insert((int)ctx->ret);
	} else {
		/* Make sure fd is not in the interesting descriptors set */
		fdset.erase((int)ctx->ret);
	}
}

#define skip_whitespace(p) \
	do {\
		while (isspace(*(p)) && *(p) != '\0') (p)++;\
	} while (0)

/*
 * Parse a line from the tracked files list file.
 */
static bool
parse_fslist_line(char *line, size_t len)
{
	char *type, *path;
	pair<set<string>::iterator, bool> res;

	//cout << "Line: " << line << endl;

	/* Ignore whitespace */
	type = line;
	skip_whitespace(type);

	/* Stop processing if line is a comment or empty */
	if (*type == '#' || *type == '\0')
		return true;

	/* Split line to TYPE: PATH */
	path = strchr(type, ':');
	if (!path)
		return false;
	*path++ = '\0';

	/* Ignore whitespace */
	skip_whitespace(path);

	/* check type */
	if (strcmp(type, "FILE") == 0) {
		//cout << "Tracking file " << path << endl;

		/* Add file to set of tracked files */
		res = tracked_files.insert(path);
		if (!res.second) {
			cerr << "Warning: " << path << 
				" has beed declared twice" << endl;
		}
	} else {
		cout << "File type " << type << " not supported" << endl;
		return false;
	}

	return true;
}

/*
 * Load list of files that needs to be tracked.
 */
static bool
load_fslist(const char *fn)
{
	size_t lineno;
	fstream fin;
	bool ret = true;
	char line[PATH_MAX + PATH_TYPE_MAX];

	fin.open(fn, ios_base::in);
	if (fin.fail())
		goto ioerror;

	lineno = 0;
	while (true) {
		lineno++;
		/* read a line from the file */
		fin.getline(line, sizeof(line));
		if (fin.eof())
			break;
		else if (fin.fail())
			goto ioerror;

		/* try to parse it */
		if (!parse_fslist_line(line, fin.gcount())) {
			cerr << "Parse error in line " << lineno << " of " 
				<< fn << endl;
			ret = false;
			break;
		}
	}

	fin.close();
	return ret;

ioerror:
	cerr << "Failed to read tracked files from " << fn << ": " <<
		strerror(errno) << endl;
	if (fin.is_open())
		fin.close();
	return false;
}

static inline void
autocorrect_version(TRACE trace)
{
	INS ins;
	BBL bbl;

#ifdef PARTITIONED_DTA_DEBUG
	stringstream ss;
	ss << "Instrumenting trace at " << (void *)TRACE_Address(trace) << 
		" to autocorrect version" << endl;
	LOG(ss.str());
#endif

	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			INS_InsertVersionCase(ins, version_reg, 
					DEFAULT_VERSION, DEFAULT_VERSION);
			INS_InsertVersionCase(ins, version_reg, 
					DTA_VERSION, DTA_VERSION);
		} // for (ins)
	} // for (bbl)
}

/* Mark address following system call instruction */
static inline void 
mark_post_syscall_ins(TRACE trace, INS ins)
{
	ADDRINT addr, trace_addr;
	pair<set<ADDRINT>::iterator, bool> res;

	/* Address of instruction following syscall */
	addr = INS_Address(ins) + INS_Size(ins);

	/* Store the address so we can later instrument it */
	res = postsyscall_ins.insert(addr);
	if (!res.second)
		return; /* We've encoutered this before */

	/* If the instruction is located in this trace do not invalidate it.
	 * We can instrument it on the fly now */
	trace_addr = TRACE_Address(trace);
	if (addr < trace_addr && addr >= (trace_addr + TRACE_Size(trace)))
		CODECACHE_InvalidateTraceAtProgramAddress(trace_addr);
}

/* Instrument post-syscall instruction to enable DTA when necessary */
static inline void
postsyscall_dta_activation(TRACE trace)
{
	INS ins;
	BBL bbl;
	set<ADDRINT>::iterator res;
	bool next_is_syscall;

	for (bbl = TRACE_BblHead(trace), next_is_syscall = false; 
			BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			if (INS_IsSyscall(ins)) {
				/* Mark syscall instructions
				 * XXX: This can be done more efficiently. We
				 * only need to change versions after open(2) */
				mark_post_syscall_ins(trace, ins);
				next_is_syscall = true;
				continue;
			} else if (next_is_syscall) {
				/* This instruction follows a syscall
				 * instruction */

#ifdef PARTITIONED_DTA_DEBUG
				stringstream ss;
				ss << "Install dta activation to instruction "
					"following syscall at " << 
					(void *)INS_Address(ins) << endl;
				LOG(ss.str());
#endif

				/* Install check to change version */
				INS_InsertVersionCase(ins, version_reg, 
						DTA_VERSION, DTA_VERSION);

				next_is_syscall = false;
			}
		} /* for (ins) */
	} /* for (bbl) */

	/* Check if trace begins right after a system call */
	res = postsyscall_ins.find(TRACE_Address(trace));
	if (res != postsyscall_ins.end()) {
		/* Ensure that the instruction is valid */
		bbl = TRACE_BblHead(trace);
		assert(BBL_Valid(bbl));
		ins = BBL_InsHead(bbl);
		assert(INS_Valid(ins));

#if 0
#ifdef PARTITIONED_DTA_DEBUG
		stringstream ss;
		ss << "Install dta activation to pre-marked instruction at " <<
			(void *)INS_Address(ins) << endl;
		LOG(ss.str());
#endif
#endif
		/* Install check to change version */
		INS_InsertVersionCase(ins, version_reg, 
				DTA_VERSION, DTA_VERSION);
	}
}

/* Instrument instructions to return to the correct version */
static VOID 
trace_instrument(TRACE trace, VOID *v)
{
	ADDRINT version;

	version = TRACE_Version(trace);
	if (version == AUTOCORRECT_VERSION)
		autocorrect_version(trace);
	else if (version == DEFAULT_VERSION)
		postsyscall_dta_activation(trace);
}

/* Make sure new threads have the version register set to the correct valu */
static VOID 
thread_start(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	ADDRINT version;

	version = PIN_GetContextReg(ctx, version_reg);

#ifdef PARTITIONED_DTA_DEBUG
	stringstream ss;
	ss << "Thread " << tid << " executing in version " << version << endl;
#endif

	if (version == AUTOCORRECT_VERSION) {
		PIN_SetContextReg(ctx, version_reg, DEFAULT_VERSION);
#ifdef PARTITIONED_DTA_DEBUG
		ss << " Thread " << tid << " switched to version " << 
			DEFAULT_VERSION << endl;
	}
	LOG(ss.str());
#else
	}
#endif
}

/* 
 * Partitioned DTA
 */
int
main(int argc, char **argv)
{
	ADDRINT ver;

	/* initialize symbol processing */
	PIN_InitSymbols();
	
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv))) {
		cerr << KNOB_BASE::StringKnobSummary() << endl;
		/* Pin initialization failed */
		return EXIT_FAILURE;
	}

	/* Load list of files that need to be tracked */
//	cout<< fslist.Value(); 
	if (!fslist.Value().empty() && !load_fslist(fslist.Value().c_str()))
		return EXIT_FAILURE;

	if (partitioned.Value()) {
		/* Claim register to hold a thread's instrumentation version */
		version_reg = PIN_ClaimToolRegister();
		assert(version_reg != REG_INVALID());

		/* Instrument callback */
		TRACE_AddInstrumentFunction(trace_instrument, 0);

		/* Thread start callback */
		PIN_AddThreadStartFunction(thread_start, 0);

		/* Set version mask for libdft */
		ver = DTA_VERSION;
	} else
		ver = 0;

	/* initialize the core tagging engine */
	if (unlikely(libdft_init(ver) != 0))
		/* failed */
		goto err;

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

	/* pread(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	/* socket(2), accept(2), recv(2), recvfrom(2), recvmsg(2) */
	/*
	(void)syscall_set_post(&syscall_desc[__NR_socketcall],
		post_socketcall_hook);
	*/

	/* dup(2), dup2(2) */
	(void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);

	/* close(2) */
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);
	
	/* open(2), creat(2) */
	if (!fslist.Value().empty()) {
		(void)syscall_set_post(&syscall_desc[__NR_open],
				post_open_hook);
		(void)syscall_set_post(&syscall_desc[__NR_creat],
				post_open_hook);
	}

	/* 
	 * install taint-sinks
	 */

	/* write(2)  XXX: add send(), sendto(), writev(), etc. */
	if (!fslist.Value().empty()) {
		(void)syscall_set_pre(&syscall_desc[__NR_write],
				pre_write_hook);
	}
	
	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
