#ifndef SRC_RPP_H_
#define SRC_RPP_H_

struct rpki_certificate;

struct rpp {
	unsigned int id;	/* For default name generation */

	char *caRepository;	/* Base rsync URI */
	char *rpkiManifest;	/* rsync URI of the manifest */
	char *crldp;		/* rsync URI of the CRL */
	char *rpkiNotify;	/* HTTP URI of the RRDP notification */

	char *path;		/* Location where we'll store it */
};

char *generate_uri(struct rpki_certificate *, char const *);
char *generate_path(struct rpki_certificate *, char const *);
struct rpp rpp_new(void);

#endif /* SRC_RPP_H_ */
