#ifndef SRC_PRINT_H_
#define SRC_PRINT_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define C_RED		"\x1B[31m"
#define C_GRN		"\x1B[32m"
#define C_YLLW		"\x1B[33m"
#define C_BLUE		"\x1B[34m"
#define C_PRPL		"\x1B[35m"
#define C_CYAN		"\x1B[36m"
#define C_WHT		"\x1B[37m"
#define C_RST		"\x1B[0m"

extern unsigned int verbosity;
extern bool print_colors;

void pr_start(FILE *, char const *);
void pr_end(FILE *);

#define pr_debug(fmt, ...) do {						\
		if (verbosity >= 1) {					\
			pr_start(stdout, C_GRN);			\
			printf("[DBG %10.10s:%4.4d] " fmt,		\
			    __func__, __LINE__, ##__VA_ARGS__);		\
			pr_end(stdout);					\
		}							\
	} while (0)

#define pr_trace(fmt, ...) do {						\
		if (verbosity >= 2) {					\
			pr_start(stdout, C_CYAN);			\
			printf("[TRC %10.10s:%4.4d] " fmt,		\
			    __func__, __LINE__, ##__VA_ARGS__);		\
			pr_end(stdout);					\
		}							\
	} while (0)
#define PR_TRACE pr_trace

#define pr_warn(fmt, ...) do {						\
		pr_start(stderr, C_YLLW);				\
		fprintf(stderr, "[WRN %10.10s:%4.4d] " fmt,		\
		    __func__, __LINE__, ##__VA_ARGS__);			\
		pr_end(stderr);						\
	} while (0)

#define pr_err(fmt, ...) do {						\
		pr_start(stderr, C_RED);				\
		fprintf(stderr, "[ERR %10.10s:%4.4d] " fmt,		\
		    __func__, __LINE__, ##__VA_ARGS__);			\
		pr_end(stderr);						\
	} while (0)

#define panic(fmt, ...) do {						\
		pr_start(stderr, C_RED);				\
		fprintf(stderr, "[ERR %s:%d] " fmt,			\
		    __func__, __LINE__, ##__VA_ARGS__);			\
		pr_end(stderr);						\
		exit(1);						\
	} while (0)

#define enomem panic("Out of memory")

#define PR_HELLO do {							\
		pr_start(stdout, C_GRN);				\
		printf("[DBG %s:%d]", __func__, __LINE__);		\
		pr_end(stdout);						\
	} while (0)

void register_signal_handlers(void);

#endif /* SRC_PRINT_H_ */
