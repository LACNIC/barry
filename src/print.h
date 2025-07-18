#ifndef SRC_PRINT_H_
#define SRC_PRINT_H_

#include <stdio.h>

#define C_RED		"\x1B[31m"
#define C_GRN		"\x1B[32m"
#define C_YLLW		"\x1B[33m"
#define C_BLUE		"\x1B[34m"
#define C_PRPL		"\x1B[35m"
#define C_CYAN		"\x1B[36m"
#define C_WHT		"\x1B[37m"
#define C_RST		"\x1B[0m"

extern unsigned int verbosity;

#define pr_debug(fmt, ...) do {						\
		if (verbosity >= 1)					\
			printf(C_GRN "[DBG %10.10s:%4.4d] " fmt C_RST "\n",\
			    __func__, __LINE__, ##__VA_ARGS__);		\
	} while (0)

#define pr_trace(fmt, ...) do {						\
		if (verbosity >= 2)					\
			printf(C_CYAN "[TRC %10.10s:%4.4d] " fmt C_RST "\n",\
			    __func__, __LINE__, ##__VA_ARGS__);		\
	} while (0)

#define panic(fmt, ...) do {						\
		fprintf(stderr, C_RED "[ERR %s:%d] " fmt C_RST "\n",	\
		    __func__, __LINE__, ##__VA_ARGS__);			\
		exit(1);						\
	} while (0)

#define enomem panic("Out of memory")

#define PR_DEBUG printf(C_GRN "[DBG %s:%d]" C_RST "\n", __func__, __LINE__)

#endif /* SRC_PRINT_H_ */
