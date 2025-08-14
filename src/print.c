#include "print.h"

#ifdef BACKTRACE_ENABLED

#include <errno.h>
#include <execinfo.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void
sigsegv_handler(int signum)
{
	/*
	 * IMPORTANT: See https://stackoverflow.com/questions/29982643
	 * I went with rationalcoder's answer, because I think not printing
	 * stack traces on segfaults is a nice way of ending up committing
	 * suicide.
	 *
	 * Here's a list of legal functions:
	 * https://stackoverflow.com/a/16891799/1735458
	 * (Man, I wish POSIX standards were easier to link to.)
	 */

#define STACK_SIZE 64
	void *array[STACK_SIZE];
	size_t size;

	size = backtrace(array, STACK_SIZE);
	backtrace_symbols_fd(array, size, STDERR_FILENO);

	/* Trigger default handler. */
	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

#endif

void
register_signal_handlers(void)
{
#ifdef BACKTRACE_ENABLED
	struct sigaction action;
	void* dummy;

	/*
	 * Make sure libgcc is loaded; otherwise backtrace() might allocate
	 * during a signal handler. (Which is illegal.)
	 */
	dummy = NULL;
	backtrace(&dummy, 1);

	/* Register the segmentation fault handler */
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigsegv_handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGSEGV, &action, NULL) == -1) {
		/*
		 * Not fatal; it just means we will not print stack traces on
		 * Segmentation Faults.
		 */
		pr_err("SIGSEGV handler registration failure: %s",
		    strerror(errno));
	}
#endif
}
