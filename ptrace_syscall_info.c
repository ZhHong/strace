/*
 * Copyright (c) 2018 The strace developers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include "kill_save_errno.h"
#include "ptrace.h"
#include "ptrace_syscall_info.h"
#include "scno.h"

#include <signal.h>
#include <sys/wait.h>

bool ptrace_get_syscall_info_supported;

bool
test_ptrace_get_syscall_info(void)
{
	static const unsigned long args[2][7] = {
		{
			__NR_chdir,
			(unsigned long) "",
			0xbad1fed1,
			0xbad2fed2,
			0xbad3fed3,
			0xbad4fed4,
			0xbad5fed5
		},
		{
			__NR_exit_group,
			0,
			0xfac1c0d1,
			0xfac2c0d2,
			0xfac3c0d3,
			0xfac4c0d4,
			0xfac5c0d5
		}
	};
	const unsigned long *exp_args;

	int pid = fork();
	if (pid < 0)
		perror_func_msg_and_die("fork");

	if (pid == 0) {
		pid = getpid();
		if (ptrace(PTRACE_TRACEME, 0L, 0L, 0L) < 0) {
			/* exit with nonzero exit status */
			perror_func_msg_and_die("PTRACE_TRACEME");
		}
		kill(pid, SIGSTOP);
		syscall(args[0][0], args[0][1], args[0][2], args[0][3],
			args[0][4], args[0][5], args[0][6]);
		syscall(args[1][0], args[1][1], args[1][2],
			args[1][3], args[1][4], args[1][5], args[1][6]);
	}

	int syscall_stop = 0;

	for (;;) {
		errno = 0;
		int status;
		int rc = wait(&status);
		if (rc <= 0) {
			if (errno == EINTR)
				continue;
			kill_save_errno(pid, SIGKILL);
			perror_func_msg_and_die("unexpected wait result %d", rc);
		} else if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0)
				break;
			error_func_msg_and_die("unexpected exit status %u",
					       WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			error_func_msg_and_die("unexpected signal %u",
					       WTERMSIG(status));
		} else if (!WIFSTOPPED(status)) {
			kill(pid, SIGKILL);
			error_func_msg_and_die("unexpected wait status %x",
					       status);
		} else if (WSTOPSIG(status) == SIGSTOP) {
			if (ptrace(PTRACE_SETOPTIONS, pid, 0L,
				   PTRACE_O_TRACESYSGOOD) < 0)
				perror_func_msg_and_die("PTRACE_SETOPTIONS");
		} else if (WSTOPSIG(status) == (SIGTRAP | 0x80) &&
			   syscall_stop >= 0) {
			struct ptrace_syscall_info info = { .op = 0xff };
			const size_t size =
				offsetofend(struct ptrace_syscall_info, entry);
			rc = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
				    (void *) size, &info);
			if (rc <= 0)
				syscall_stop = -1;
			else switch (syscall_stop) {
				case 0: /* entering chdir */
				case 2: /* entering exit_group */
					exp_args = args[syscall_stop != 0];
					if (info.op == PTRACE_SYSCALL_INFO_ENTRY
					    && (info.entry.nr == exp_args[0])
					    && (info.entry.args[0] == exp_args[1])
					    && (info.entry.args[1] == exp_args[2])
					    && (info.entry.args[2] == exp_args[3])
					    && (info.entry.args[3] == exp_args[4])
					    && (info.entry.args[4] == exp_args[5])
					    && (info.entry.args[5] == exp_args[6])) {
						++syscall_stop;
					} else {
						debug_func_msg("syscall stop"
							       " %d mismatch",
							       syscall_stop);
						syscall_stop = -1;
					}
					break;
				case 1: /* exiting chdir */
					if (info.op == PTRACE_SYSCALL_INFO_EXIT
					    && info.exit.is_error == 1
					    && info.exit.rval == -ENOENT) {
						++syscall_stop;
					} else {
						debug_func_msg("syscall stop"
							       " %d mismatch",
							       syscall_stop);
						syscall_stop = -1;
					}
					break;
				default:
					debug_func_msg("unexpected syscall stop");
					syscall_stop = -1;
			}
		}
		if (ptrace(PTRACE_SYSCALL, pid, 0L, 0L) < 0) {
			kill_save_errno(pid, SIGKILL);
			perror_func_msg_and_die("PTRACE_SYSCALL");
		}
	}

	ptrace_get_syscall_info_supported = syscall_stop == 3;

	if (ptrace_get_syscall_info_supported)
		debug_msg("PTRACE_GET_SYSCALL_INFO works");
	else
		debug_msg("PTRACE_GET_SYSCALL_INFO does not work");

	return ptrace_get_syscall_info_supported;
}
