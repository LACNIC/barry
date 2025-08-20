#include "rpki_object.h"

#include "cer.h"
#include "csv.h"

void
meta_print_csv(struct rpki_object *meta)
{
	struct rpki_certificate *parent;

	csv_print3(meta, "uri", meta->uri);
	csv_print3(meta, "path", meta->path);

	parent = meta->parent;
	csv_print3(meta, "parent", parent ? parent->meta->name : "");
}
