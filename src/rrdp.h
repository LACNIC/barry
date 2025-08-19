#ifndef SRC_OBJ_RRDP_H_
#define SRC_OBJ_RRDP_H_

struct rrdp_type;
extern const struct rrdp_type SNAPSHOT;
extern const struct rrdp_type DELTA;

struct rrdp_entry_type;
extern const struct rrdp_entry_type PUBLISH;
extern const struct rrdp_entry_type WITHDRAW;

struct rrdp_entry_file {
	struct rrdp_entry_type const *type;
	char const *uri;
	char const *path;
	char *hash;
};

void rrdp_save(char const *, struct rrdp_type const *,
    struct rrdp_entry_file *, unsigned int);

#endif /* SRC_OBJ_RRDP_H_ */
