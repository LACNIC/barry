#ifndef SRC_FILE_H_
#define SRC_FILE_H_

#include <stdbool.h>

char *join_paths(char const *, char const *);
char *remove_extension(char const *);

int write_open(char const *);

void exec_mkdir(char *);
void exec_mkdir_p(char const *, bool);

#endif /* SRC_FILE_H_ */
