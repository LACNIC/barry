#ifndef SRC_FILE_H_
#define SRC_FILE_H_

#include <stdbool.h>
#include "uthash.h"

char *join_paths(char const *, char const *);
char *remove_extension(char const *);

int write_open(char const *);

void exec_mkdir(char *);
void exec_mkdir_p(char const *, bool);

void exec_rm_rf_content(char const *);

struct filepath_node {
	char *name;
	char *path;
	UT_hash_handle hh;
};

struct filepath_ht {
	struct filepath_node *nodes;
};

void dir_index(struct filepath_ht *, char const *);
char const *dir_find(struct filepath_ht *, char const *);

#endif /* SRC_FILE_H_ */
