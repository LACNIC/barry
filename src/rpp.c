#include "rpp.h"

#include <string.h>
#include "alloc.h"
#include "cer.h"
#include "print.h"

extern char *rsync_uri;
extern char *rsync_path;
unsigned int rpp_counter;

static char *
join_paths(char const *base, char const *filename)
{
	size_t nbase, nfilename, nresult;
	char *result;

	nbase = strlen(base);
	nfilename = strlen(filename);

	if (base[nbase - 1] == '/')
		nbase--;
	if (filename[0] == '/') {
		filename++;
		nfilename--;
	}

	nresult = nbase + nfilename + 2;
	result = pmalloc(nresult);

	strncpy(result, base, nbase);
	result[nbase] = '/';
	strncpy(result + nbase + 1, filename, nfilename);
	result[nresult -1] = '\0';

	return result;
}

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

struct rpp
rpp_new(void)
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

	result.rpkiNotify = NULL;
	/*
	psnprintf(name, NAME_SIZE, "%X.xml", result.id);
	result.rpkiNotify = join_paths(rrdp_uri, name);
	pr_debug("- RPP rpkiNotify: %s", result.rpkiNotify);
	*/

	return result;
}
