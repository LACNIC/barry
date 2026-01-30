#ifndef SRC_GLOBAL_H_
#define SRC_GLOBAL_H_

#include <stdbool.h>
#include <libasn1fort/GeneralizedTime.h>
#include <libasn1fort/Time.h>

char const *repo_descriptor;
char const *rsync_uri = "rsync://localhost:8873/rpki";
char const *rsync_path = "rsync/";
char const *rrdp_uri = "https://localhost:8443/rrdp";
char const *rrdp_path = "rrdp/";
char const *tal_path;
Time_t default_now;
Time_t default_later;
GeneralizedTime_t default_gnow;
GeneralizedTime_t default_glater;
char const *keys_path;
char const *print_format;
unsigned int verbosity;
bool print_colors;

#endif /* SRC_GLOBAL_H_ */
