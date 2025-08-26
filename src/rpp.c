#include "rpp.h"

#include "alloc.h"
#include "cer.h"
#include "file.h"

extern char *rsync_uri;

char *
generate_uri(struct rpki_certificate *parent, char const *filename)
{
	return join_paths(
	    parent ? parent->rpp.uri : rsync_uri,
	    filename
	);
}

char *
generate_path(struct rpki_certificate *parent, char const *filename)
{
	return parent
	    ? join_paths(parent->rpp.path, filename)
	    : pstrdup(filename);
}
