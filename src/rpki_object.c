#include "rpki_object.h"

#include "cer.h"
#include "csv.h"

void
meta_print_csv(struct rpki_object *meta, char const *type)
{
	struct rpki_certificate *parent;

	csv_print3(meta, "uri", meta->uri);
	csv_print3(meta, "path", meta->path);
	csv_print3(meta, "type", type);

	parent = meta->parent;
	csv_print3(meta, "parent", parent ? parent->meta->name : "");
}
