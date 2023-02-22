/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
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

#ifndef __LIBDFT_API_H__
#define __LIBDFT_API_H__

#include <sys/syscall.h>

#include "linux_kernver.h"
#include "pin.H"

#if LINUX_KERNEL < 2626
#error "Your kernel is tool old and this version of libdft does not support it"
#elif LINUX_KERNEL == 2626
#define SYSCALL_MAX	__NR_timerfd_gettime+1	/* max syscall number */
#elif LINUX_KERNEL >= 2627 && LINUX_KERNEL <=2629
#define SYSCALL_MAX	__NR_inotify_init1+1	/* max syscall number */
#elif LINUX_KERNEL == 2630
#define SYSCALL_MAX	__NR_pwritev+1		/* max syscall number */
#elif LINUX_KERNEL == 2631
#define SYSCALL_MAX	__NR_perf_counter_open+1/* max syscall number */
#elif LINUX_KERNEL == 2632
#define SYSCALL_MAX	__NR_perf_event_open+1	/* max syscall number */
#elif LINUX_KERNEL >= 2633 && LINUX_KERNEL <=2635
#define SYSCALL_MAX	__NR_recvmmsg+1		/* max syscall number */
#elif LINUX_KERNEL >= 2636 && LINUX_KERNEL <=2638
#define SYSCALL_MAX	__NR_prlimit64+1	/* max syscall number */
#else
#define SYSCALL_MAX	__NR_syncfs+1		/* max syscall number */
#endif
#define SYSCALL_ARG_NUM	6			/* syscall arguments */
#define SYSCALL_ARG0	0			/* 1st argument in syscall */
#define SYSCALL_ARG1	1			/* 2nd argument in syscall */
#define SYSCALL_ARG2	2			/* 3rd argument in syscall */
#define SYSCALL_ARG3	3			/* 4th argument in syscall */
#define SYSCALL_ARG4	4			/* 5th argument in syscall */
#define SYSCALL_ARG5	5			/* 6th argument in syscall */
#define GRP_NUM		8			/* general purpose registers */
						/* default action
						 * enable/disable
						 * (ins_desc_t) */
#define INSDFL_ENABLE   0
#define INSDFL_DISABLE  1

/* FIXME: turn off the EFLAGS.AC bit by applying the corresponding mask */
#define CLEAR_EFLAGS_AC(eflags)	((eflags & 0xfffbffff))


/*
 * virtual CPU (VCPU) context definition;
 * x86/x86_32/i386 arch
 */
typedef struct {
	/*
	 * general purpose registers (GPRs)
	 *
	 * we assign one bit of tag information for
	 * for every byte of addressable memory; the 32-bit
	 * GPRs of the x86 architecture will be represented
	 * with 4 bits each (the lower 4 bits of a 32-bit
	 * unsigned integer)
	 *
	 * NOTE the mapping:
	 * 	0: EDI
	 * 	1: ESI
	 * 	2: EBP
	 * 	3: ESP
	 * 	4: EBX
	 * 	5: EDX
	 * 	6: ECX
	 * 	7: EAX
	 * 	8: scratch (not a real register; helper) 
	 */
	uint32_t gpr[GRP_NUM + 1];
} vcpu_ctx_t;

/*
 * system call context definition
 *
 * only up to SYSCALL_ARGS (i.e., 6) are saved
 */
typedef struct {
	int 	nr;			/* syscall number */
	ADDRINT arg[SYSCALL_ARG_NUM];	/* arguments */
	ADDRINT ret;			/* return value */
	void	*aux;			/* auxiliary data (processor state) */
/* 	ADDRINT errno; */		/* error code */
} syscall_ctx_t;

/* thread context definition */
typedef struct {
	vcpu_ctx_t	vcpu;		/* VCPU context */
	syscall_ctx_t	syscall_ctx;	/* syscall context */
	void*		uval;		/* local storage */
} thread_ctx_t;

/* instruction (ins) descriptor */
typedef struct {
	void	(* pre)(INS ins);	/* pre-ins instrumentation callback */
	void	(* post)(INS ins);	/* post-ins instrumentation callback */
	size_t	dflact;                 /* default instrumentation predicate */
} ins_desc_t;


/* libdft API */
int	libdft_init(int, char**);
void	libdft_start(void);
void	libdft_die(void);

/* ins API */
int	ins_set_pre(ins_desc_t*, void (*)(INS));
int	ins_clr_pre(ins_desc_t*);
int	ins_set_post(ins_desc_t*, void (*)(INS));
int	ins_clr_post(ins_desc_t*);
int	ins_set_dflact(ins_desc_t *desc, size_t action);

/* REG API */
size_t	REG32_INDX(REG);
size_t	REG16_INDX(REG);
size_t	REG8_INDX(REG);

#endif /* __LIBDFT_API_H__ */
