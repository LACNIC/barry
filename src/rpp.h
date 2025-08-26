#ifndef SRC_RPP_H_
#define SRC_RPP_H_

struct rpki_certificate;

struct rpp {
	char *uri;		/* Base rsync URI */
	char *path;		/* Location where we'll store the RPP */
	char *notification;	/* HTTP URI of the RRDP Notification */
};

char *generate_uri(struct rpki_certificate *, char const *);
char *generate_path(struct rpki_certificate *, char const *);

#endif /* SRC_RPP_H_ */
