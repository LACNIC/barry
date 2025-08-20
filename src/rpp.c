#include "rpp.h"

#include <string.h>
#include "alloc.h"
#include "cer.h"
#include "file.h"
#include "print.h"

extern char *rsync_uri;
extern char *rsync_path;
unsigned int rpp_counter;

char *
generate_uri(struct rpki_certificate *parent, char const *filename)
{
	return join_paths(
	    parent ? parent->rpp.caRepository : rsync_uri,
	    filename
	);
}

char *
generate_path(struct rpki_certificate *parent, char const *filename)
{
	return join_paths(parent ? parent->rpp.path : rsync_path, filename);
}

static char *
autocompute_notify(struct rpki_certificate *cer)
{
	extern char const *rrdp_uri;
	char *rpkiNotify;

	if (rrdp_uri == NULL)
		return NULL;
	if (cer->meta->parent != NULL)
		return NULL; /* Everything except TA inherits by default */

	rpkiNotify = join_paths(rrdp_uri, "notification.xml");
	notif_getsert(cer->meta->tree, rpkiNotify);
	return rpkiNotify;
}

struct rpp
rpp_new(struct rpki_certificate *cer)
{
#define NAME_SIZE 64
	char name[NAME_SIZE];
	struct rpp result;

	result.id = rpp_counter++;
	psnprintf(name, NAME_SIZE, "rpp%X", result.id);
	pr_debug("- RPP name: %s", name);

	result.caRepository = join_paths(rsync_uri, name);
	pr_debug("- RPP caRepository: %s", result.caRepository);
	result.path = join_paths(rsync_path, name);
	pr_debug("- RPP path: %s", result.path);

	psnprintf(name, NAME_SIZE, "%X.mft", result.id);
	result.rpkiManifest = join_paths(result.caRepository, name);
	pr_debug("- RPP rpkiManifest: %s", result.path);

	psnprintf(name, NAME_SIZE, "%X.crl", result.id);
	result.crldp = join_paths(result.caRepository, name);
	pr_debug("- RPP CRL: %s", result.path);

	result.rpkiNotify = autocompute_notify(cer);
	pr_debug("- RPP rpkiNotify: %s", result.rpkiNotify);

	return result;
}
