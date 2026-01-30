#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asa.h"
#include "asn1.h"
#include "crl.h"
#include "file.h"
#include "mft.h"
#include "roa.h"
#include "rrdp.h"
#include "sha.h"
#include "tal.h"

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

#define OPTLONG_RSYNC_URI	"rsync-uri"
#define OPTLONG_RSYNC_PATH	"rsync-path"
#define OPTLONG_RRDP_URI	"rrdp-uri"
#define OPTLONG_RRDP_PATH	"rrdp-path"
#define OPTLONG_TAL_PATH	"tal-path"
#define OPTLONG_NOW		"now"
#define OPTLONG_LATER		"later"
#define OPTLONG_KEYS		"keys"
#define OPTLONG_PR_OBJS		"print-objects"
#define OPTLONG_VERBOSE		"verbose"
#define OPTLONG_COLOR		"color"
#define OPTLONG_HELP		"help"

static void
print_help(void)
{
	printf("Usage: barry	[--" OPTLONG_RSYNC_URI "=<URL>]\n");
	printf("		[--" OPTLONG_RSYNC_PATH "=<Path>]\n");
	printf("		[--" OPTLONG_RRDP_URI "=<URL>]\n");
	printf("		[--" OPTLONG_RRDP_PATH "=<Path>]\n");
	printf("		[--" OPTLONG_TAL_PATH "=<Path>]\n");
	printf("		[--" OPTLONG_NOW "=<Datetime>]\n");
	printf("		[--" OPTLONG_LATER "=<Datetime>]\n");
	printf("		[--" OPTLONG_KEYS "=<Path>]\n");
	printf("		[--" OPTLONG_PR_OBJS "=(csv|markdown)]\n");
	printf("		[--" OPTLONG_VERBOSE " [--" OPTLONG_VERBOSE "]]\n");
	printf("		[--" OPTLONG_COLOR "]\n");
	printf("		[--" OPTLONG_HELP "]\n");
	printf("		<Path>    # Repository Descriptor\n");
}

static void
init_times(char const *optnow, char const *optlater)
{
	time_t now_t;
	struct tm tm;

	now_t = time(NULL);
	if (now_t == ((time_t) -1))
		panic("Cannot get the current time: %s", strerror(errno));
	if (gmtime_r(&now_t, &tm) != &tm)
		panic("Cannot convert current time to tm format; unknown cause.");

	if (optnow != NULL) {
		init_time_str(&default_now, optnow);
		init_gtime_str(&default_gnow, optnow);
	} else {
		init_time_tm(&default_now, &tm);
		init_gtime_tm(&default_gnow, &tm);
	}

	if (optlater != NULL) {
		init_time_str(&default_later, optlater);
		init_gtime_str(&default_glater, optlater);
	} else {
		tm.tm_year++;
		init_time_tm(&default_later, &tm);
		init_gtime_tm(&default_glater, &tm);
	}
}

static void
parse_options(int argc, char **argv)
{
	static struct option opts[] = {
		{ OPTLONG_RSYNC_URI,  required_argument, 0, 1024 },
		{ OPTLONG_RSYNC_PATH, required_argument, 0, 1025 },
		{ OPTLONG_RRDP_URI,   required_argument, 0, 1028 },
		{ OPTLONG_RRDP_PATH,  required_argument, 0, 1027 },
		{ OPTLONG_TAL_PATH,   required_argument, 0, 't' },
		{ OPTLONG_NOW,        required_argument, 0, 'P' },
		{ OPTLONG_LATER,      required_argument, 0, 1026 },
		{ OPTLONG_KEYS,       required_argument, 0, 'k' },
		{ OPTLONG_PR_OBJS,    required_argument, 0, 'p' },
		{ OPTLONG_VERBOSE,    no_argument,       0, 'v' },
		{ OPTLONG_COLOR,      no_argument,       0, 'c' },
		{ OPTLONG_HELP,       no_argument,       0, 'h' },
		{ 0 }
	};
	int opt;
	char *optnow = NULL;
	char *optlater = NULL;

	while ((opt = getopt_long(argc, argv, "t:P:k:p:vch", opts, NULL)) != -1) {
		switch (opt) {
		case 1024:
			rsync_uri = optarg;
			break;
		case 1025:
			rsync_path = optarg;
			break;
		case 1028:
			rrdp_uri = optarg;
			break;
		case 1027:
			rrdp_path = optarg;
			break;
		case 't':
			tal_path = optarg;
			break;
		case 'P':
			optnow = optarg;
			break;
		case 1026:
			optlater = optarg;
			break;
		case 'k':
			keys_path = optarg;
			break;
		case 'p':
			print_format = optarg;
			break;
		case 'v':
			verbosity++;
			break;
		case 'c':
			print_colors = true;
			break;
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case '?':
			print_help();
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		print_help();
		exit(EXIT_FAILURE);
	}

	repo_descriptor = argv[optind];
	if (tal_path == NULL)
		tal_path = tal_autogenerate_path(repo_descriptor);
	init_times(optnow, optlater);

	pr_debug("Configuration:");
	pr_debug("   Repository Descriptor"          ": %s", repo_descriptor);
	pr_debug("   --" OPTLONG_RSYNC_URI "          : %s", rsync_uri);
	pr_debug("   --" OPTLONG_RSYNC_PATH "         : %s", rsync_path);
	pr_debug("   --" OPTLONG_RRDP_URI "           : %s", rrdp_uri);
	pr_debug("   --" OPTLONG_RRDP_PATH "          : %s", rrdp_path);
	pr_debug("   --" OPTLONG_TAL_PATH "       (-t): %s", tal_path);
	pr_debug("   --" OPTLONG_NOW "            (-P): %s", optnow);
	pr_debug("   --" OPTLONG_LATER "              : %s", optlater);
	pr_debug("   --" OPTLONG_KEYS "               : %s", keys_path);
	pr_debug("   --" OPTLONG_PR_OBJS       "  (-p): %s", print_format);
	pr_debug("   --" OPTLONG_VERBOSE "        (-v): %u", verbosity);
	pr_debug("   --" OPTLONG_COLOR "          (-c): %u", print_colors);
	pr_debug("");
}

static enum file_type
str2ft(struct rpki_tree_node *node, char const *str)
{
	if (strcmp(str, "cer") == 0)
		return (node->parent == NULL) ? FT_TA : FT_CER;
	if (strcmp(str, "crl") == 0)
		return FT_CRL;
	if (strcmp(str, "mft") == 0)
		return FT_MFT;
	if (strcmp(str, "roa") == 0)
		return FT_ROA;
	if (strcmp(str, "asa") == 0 || strcmp(str, "aspa") == 0)
		return FT_ASA;
	return FT_UNKNOWN;
}

static enum file_type
infer_type(struct rpki_tree_node *node)
{
	struct kv_value *type_kv;
	size_t namelen;
	char *extension;
	enum file_type result;

	type_kv = keyvals_find(&node->props, "type");
	if (type_kv != NULL) {
		if (type_kv->type != VALT_STR)
			panic("type: Expected a string value");

		result = str2ft(node, type_kv->v.str);
		if (result == FT_UNKNOWN)
			panic("Unknown type: %s", type_kv->v.str);

		return result;
	}

	namelen = strlen(node->meta.name);
	if (namelen < 4)
		return FT_UNKNOWN;
	extension = node->meta.name + namelen - 4;
	return (extension[0] == '.') ? str2ft(node, extension + 1) : FT_UNKNOWN;
}

static struct rpki_tree_node *
find_child(struct rpki_tree_node *parent, enum file_type type)
{
	struct rpki_tree_node *child, *tmp;

	HASH_ITER(phook, parent->children, child, tmp)
		if (child->type == type)
			return child;

	return NULL;
}

static void
init_type(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	node->type = infer_type(node);
}

static void
init_object(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Initializing: %s", node->meta.name);

	field_add(node->fields, "type", &ft_filetype, &node->type, 0);
	field_add(node->fields, "uri", &ft_cstr, &node->meta.uri, 0);
	field_add(node->fields, "path", &ft_cstr, &node->meta.path, 0);

	switch (node->type) {
	case FT_TA:
		node->obj = cer_new(node, CT_TA);
		break;
	case FT_CER:
		node->obj = cer_new(node, CT_CA);
		break;
	case FT_CRL:
		node->obj = crl_new(node);
		break;
	case FT_MFT:
		node->obj = mft_new(node);
		break;
	case FT_ROA:
		node->obj = roa_new(node);
		break;
	case FT_ASA:
		node->obj = asa_new(node);
		break;
	default:
		panic("Unknown file type: %s", node->meta.name);
	}
}

static void
generate_paths(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	struct rpki_object *meta = &node->meta;

	pr_debug("Generating paths: %s", node->meta.name);

	if (!fields_overridden(node->fields, "uri")) {
		meta->uri = generate_uri(meta_parent(meta), meta->name);
		pr_debug("- uri: %s", meta->uri);
	}

	if (!fields_overridden(node->fields, "path")) {
		meta->path = generate_path(meta_parent(meta), meta->name);
		pr_debug("- path: %s", meta->path);
	}

	if (IS_CER(node->type))
		cer_finish_rpp(node->obj);
}

static void
create_missing_node(struct rpki_tree *tree, struct rpki_tree_node *parent,
    enum file_type type, char const *extension)
{
	struct rpki_tree_node *child;
	char *extless;

	child = pzalloc(sizeof(struct rpki_tree_node));

	extless = remove_extension(parent->meta.name);
	child->meta.name = concat(extless, extension);
	free(extless);

	child->meta.tree = tree;
	child->meta.node = child;
	child->type = type;
	child->fields = pzalloc(sizeof(struct field));

	rpkitree_add(tree, parent, child);
}

static void
add_missing_objs(struct rpki_tree *tree, struct rpki_tree_node *parent,
    void *arg)
{
	if (!IS_CER(parent->type))
		return;

	if (find_child(parent, FT_MFT) == NULL) {
		pr_debug("Need to create %s's child Manifest", parent->meta.name);
		create_missing_node(tree, parent, FT_MFT, ".mft");
	}

	if (find_child(parent, FT_CRL) == NULL) {
		pr_debug("Need to create %s's child CRL", parent->meta.name);
		create_missing_node(tree, parent, FT_CRL, ".crl");
	}
}

static void
apply_keyvals(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Applying keyvals: %s", node->meta.name);
	fields_apply_keyvals(node->fields, &node->props);
}

void
apply_notification_fields(struct rpki_tree *tree)
{
	struct rrdp_notification *notif, *tmp;

	HASH_ITER(hh, tree->notifications, notif, tmp) {
		pr_debug("Applying keyvals: %s", notif->uri);
		fields_apply_keyvals(notif->fields, &notif->props);
	}
}

static void
finish_not_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Finishing (unless it's a manifest): %s", node->meta.name);

	switch (node->type) {
	case FT_TA:
		cer_finish_ta(node->obj);
		break;
	case FT_CER:
		cer_finish_ca(node->obj);
		break;
	case FT_CRL:
		crl_finish(node->obj);
		break;
	case FT_MFT:
		break;
	case FT_ROA:
		roa_finish(node->obj);
		break;
	case FT_ASA:
		asa_finish(node->obj);
		break;
	default:
		panic("Unknown file type: %s", node->meta.name);
	}
}

static void
finish_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	if (node->type != FT_MFT)
		return;

	pr_debug("Finishing: %s", node->meta.name);
	mft_finish(node->obj, node->parent->children);
}

static void
write_not_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Writing file (unless it's a manifest): %s", node->meta.name);

	switch (node->type) {
	case FT_TA:
	case FT_CER:
		cer_write(node->obj);
		break;
	case FT_CRL:
		crl_write(node->obj);
		break;
	case FT_MFT:
		break;
	case FT_ROA:
		roa_write(node->obj);
		break;
	case FT_ASA:
		asa_write(node->obj);
		break;
	default:
		panic("Unknown file type: %s", node->meta.name);
	}
}

static void
write_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	if (node->type != FT_MFT)
		return;

	pr_debug("Writing: %s", node->meta.name);
	mft_write(node->obj);
}

static void
write_ta(struct rpki_tree_node *ta)
{
	char *rsync;
	char *rrdp;
	int error;

	rsync = join_paths(rsync_path, ta->meta.path);
	rrdp = join_paths(rrdp_path, ta->meta.name);

	exec_mkdir_p(rrdp_path, true);

	if (unlink(rrdp)) {
		error = errno;
		if (error != ENOENT)
			panic("Cannot replace HTTP TA: %s", strerror(error));
	}

	pr_trace("link %s %s", rsync, rrdp);
	if (link(rsync, rrdp) < 0)
		panic("Can't create the HTTP TA: %s", strerror(errno));

	free(rrdp);
	free(rsync);
}

void
build_notif_filelists(struct rpki_tree *tree, struct rpki_tree_node *node,
    void *arg)
{
	struct rpki_tree_node *ancestor;
	struct rpki_certificate *cer;
	struct rrdp_notification *notif;

	ancestor = node;
	while ((ancestor = ancestor->parent) != NULL) {
		if (!IS_CER(ancestor->type))
			continue;

		cer = ancestor->obj;
		if (cer->rpp.notification) {
			notif = notif_getsert(tree, cer->rpp.notification);
			if (!fields_overridden(notif->fields, "snapshot.files"))
				notif_add_file(notif, node->meta.name);
			return;
		}
	}
}

static void
write_rrdp(struct rpki_tree *tree)
{
	struct rrdp_notification *notif, *tmp;
	size_t f;
	struct rrdp_file *file;
	struct rrdp_entry_file *req;
	size_t namelen;
	struct rpki_tree_node *node;
	char *notif_path;
	char *snapshot_path;

	write_ta(tree->root);

	rpkitree_pre_order(tree, build_notif_filelists, NULL);

	HASH_ITER(hh, tree->notifications, notif, tmp) {
		if (STAILQ_EMPTY(&notif->snapshot.files))
			continue;

		pr_trace("- Notification: %s", notif->uri);

		if (notif->path == NULL) {
			pr_err("%s does not match --rrdp-uri (%s), "
			    "so I cannot autocompute a path. "
			    "Please set it manually:\n"
			    "	[notification: %s]\n"
			    "	path = some/path/here.xml",
			    notif->uri, rrdp_uri, notif->uri);
			pr_warn("Skipping %s.", notif->uri);
			continue;
		}
		if (notif->snapshot.path == NULL) {
			pr_err("%s does not match --rrdp-uri (%s), "
			    "so I cannot autocompute a path. "
			    "Please set it manually:\n"
			    "	[notification: %s]\n"
			    "	snapshot.path = some/path/here.xml",
			    notif->snapshot.uri, rrdp_uri, notif->uri);
			pr_warn("Skipping %s.", notif->uri);
			continue;
		}

		f = 0;
		STAILQ_FOREACH(file, &notif->snapshot.files, hook)
			f++;

		req = pcalloc(f, sizeof(struct rrdp_entry_file));

		f = 0;
		STAILQ_FOREACH(file, &notif->snapshot.files, hook) {
			namelen = strlen(file->name);
			HASH_FIND(ghook, tree->nodes, file->name, namelen, node);
			if (!node)
				panic("Node does not exist: %s", file->name);

			req[f].type = &PUBLISH;
			req[f].uri = node->meta.uri;
			req[f].path = node->meta.path;
//			files[f].hash = sha256_file_str(node->meta.path);

			f++;
		}

		notif_path = join_paths(rrdp_path, notif->path);
		snapshot_path = join_paths(rrdp_path, notif->snapshot.path);

		rrdp_save_snapshot(snapshot_path, &SNAPSHOT,
		    notif->snapshot.session ? notif->snapshot.session : notif->session,
		    notif->snapshot.serial ? notif->snapshot.serial : &notif->serial,
		    req, f);
		rrdp_save_notification(notif_path,
		    notif->session, &notif->serial,
		    notif->snapshot.uri, sha256_file_str(snapshot_path));

		free(snapshot_path);
		free(notif_path);

//		for (f = 0; f < count; f++)
//			free(files[f].hash);
		free(req);
	}
}

static void
print_repository_md(struct rpki_tree *tree)
{
	struct rpki_tree_node *node, *tmp;

	printf("# Tree\n\n");
	printf("```\n");
	rpkitree_print(tree);
	printf("```\n\n");

	printf("# Files\n\n");
	HASH_ITER(ghook, tree->nodes, node, tmp) {
		printf("## %s\n\n", node->meta.name);
		fields_print_md(node->fields);
		printf("\n");
	}
}

static void
print_repository_csv(struct rpki_tree *tree)
{
	struct rpki_tree_node *node, *tmp1;
	struct rrdp_notification *notif, *tmp2;

	HASH_ITER(ghook, tree->nodes, node, tmp1)
		fields_print_csv(node->fields, node->meta.name);

	HASH_ITER(hh, tree->notifications, notif, tmp2)
		if (!STAILQ_EMPTY(&notif->snapshot.files))
			fields_print_csv(notif->fields, notif->uri);
}

static void
print_repository(struct rpki_tree *tree)
{
	if (strcmp("markdown", print_format) == 0)
		print_repository_md(tree);
	else if (strcmp("csv", print_format) == 0)
		print_repository_csv(tree);
	else
		pr_err("Unknown print format: %s", print_format);
}

int
main(int argc, char **argv)
{
	struct rpki_tree tree = { 0 };

	register_signal_handlers();

	parse_options(argc, argv);

	rpkitree_load(repo_descriptor, &tree);

	pr_debug("Figuring out object types...");
	rpkitree_pre_order(&tree, init_type, NULL);
	if (tree.root->type != FT_TA)
		panic("The root of the tree is not a certificate.");
	pr_debug("Done.\n");

	pr_debug("Adding missing CRLs and Manifests...");
	rpkitree_pre_order(&tree, add_missing_objs, NULL);
	pr_debug("Done.\n");

	pr_debug("Instancing generic RPKI objects...");
	rpkitree_pre_order(&tree, init_object, NULL);
	pr_debug("Done.\n");

	pr_debug("Applying keyvals...");
	rpkitree_pre_order(&tree, apply_keyvals, NULL);
	apply_notification_fields(&tree);
	pr_debug("Done.\n");

	pr_debug("Generating default paths...");
	rpkitree_pre_order(&tree, generate_paths, NULL);
	pr_debug("Done.\n");

	pr_debug("Post-processing (except manifests)...");
	rpkitree_pre_order(&tree, finish_not_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (except manifests)...");
	rpkitree_pre_order(&tree, write_not_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Post-processing (manifests)...");
	rpkitree_pre_order(&tree, finish_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (manifests)...");
	rpkitree_pre_order(&tree, write_mfts, NULL);
	pr_debug("Done.\n");

	if (rrdp_uri[0] && rrdp_path[0]) {
		pr_debug("Writing RRDP XMLs...");
		write_rrdp(&tree);
		pr_debug("Done.\n");
	}

	pr_debug("Writing the TAL...");
	tal_write(tree.root->obj, tal_path);
	pr_debug("Done.");

	if (print_format) {
		pr_debug("Printing objects...");
		print_repository(&tree);
		pr_debug("Done.\n");
	}

	return 0;
}
