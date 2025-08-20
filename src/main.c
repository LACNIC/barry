#include <errno.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "asn1.h"
#include "cer.h"
#include "crl.h"
#include "file.h"
#include "libcrypto.h"
#include "mft.h"
#include "print.h"
#include "roa.h"
#include "rpki_tree.h"
#include "rrdp.h"
#include "str.h"
#include "tal.h"

char const *repo_descriptor;
char const *rsync_uri = "rsync://localhost:8873/rpki";
char const *rsync_path = "rsync/";
char const *rrdp_uri = "https://localhost:8080/rpki";
char const *rrdp_path = "rrdp/";
char const *tal_path;
Time_t default_now;
Time_t default_later;
GeneralizedTime_t default_gnow;
GeneralizedTime_t default_glater;
char const *keys_path;
char const *print_format;
unsigned int verbosity;

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
	printf("		[--" OPTLONG_PR_OBJS "]\n");
	printf("		[--" OPTLONG_VERBOSE " [--" OPTLONG_VERBOSE "]]\n");
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
		{ OPTLONG_HELP,       no_argument,       0, 'h' },
		{ 0 }
	};
	int opt;
	char *optnow = NULL;
	char *optlater = NULL;

	while ((opt = getopt_long(argc, argv, "t:P:k:p:vh", opts, NULL)) != -1) {
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
	pr_debug("");
}

static enum file_type
infer_type(struct rpki_tree_node *node)
{
	size_t namelen;
	char *extension;

	namelen = strlen(node->meta.name);
	if (namelen < 4)
		return FT_UNKNOWN;

	extension = node->meta.name + strlen(node->meta.name) - 4;

	if (strcmp(extension, ".cer") == 0)
		return (node->parent == NULL) ? FT_TA : FT_CER;
	if (strcmp(extension, ".crl") == 0)
		return FT_CRL;
	if (strcmp(extension, ".mft") == 0)
		return FT_MFT;
	if (strcmp(extension, ".roa") == 0)
		return FT_ROA;
	return FT_UNKNOWN;
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
init_parent(struct rpki_tree_node *node)
{
	struct rpki_tree_node *parent;

	parent = node->parent;
	if (parent == NULL)
		return;
	if (parent->type == FT_TA || parent->type == FT_CER) {
		node->meta.parent = parent->obj;
		return;
	}

	panic("%s's parent is not a certificate.", node->meta.name);
}

static void
init_object(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Initializing: %s", node->meta.name);

	init_parent(node);

	switch (node->type) {
	case FT_TA:
		node->obj = cer_new(&node->meta, CT_TA);
		break;
	case FT_CER:
		node->obj = cer_new(&node->meta, CT_CA);
		break;
	case FT_CRL:
		node->obj = crl_new(&node->meta);
		break;
	case FT_MFT:
		node->obj = mft_new(node);
		break;
	case FT_ROA:
		node->obj = roa_new(&node->meta);
		break;
	default:
		panic("Unknown file type: %s", node->meta.name);
	}
}

static void
autogenerate_uri_and_path(struct rpki_tree_node *node)
{
	node->meta.uri = generate_uri(node->meta.parent, node->meta.name);
	pr_debug("- uri: %s", node->meta.uri);

	node->meta.path = generate_path(node->meta.parent, node->meta.name);
	pr_debug("- path: %s", node->meta.path);
}

static void
generate_paths(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Generating paths: %s", node->meta.name);

	autogenerate_uri_and_path(node);

	switch (node->type) {
	case FT_TA:
	case FT_CER:
		cer_generate_paths(node->obj);
		break;
	case FT_CRL:
		crl_generate_paths(node->obj);
		break;
	case FT_MFT:
		mft_generate_paths(node->obj);
		break;
	case FT_ROA:
		roa_generate_paths(node->obj);
		break;
	default:
		panic("Unknown file type: %s", node->meta.name);
	}
}

static struct rpki_tree_node *
create_missing_node(struct rpki_tree *tree, char *url,
    struct rpki_certificate *ca)
{
	struct rpki_tree_node *child;
	char *slash;

	child = pzalloc(sizeof(struct rpki_tree_node));
	slash = strrchr(url, '/');
	child->meta.name = slash ? (slash + 1) : url;
	child->meta.tree = tree;
	child->meta.parent = ca;
	child->meta.fields = pzalloc(sizeof(struct field));

	autogenerate_uri_and_path(child);

	return child;
}

static void
add_missing_objs(struct rpki_tree *tree, struct rpki_tree_node *parent,
    void *arg)
{
	struct rpki_tree_node *mft, *crl;
	struct rpki_certificate *ca;

	if (parent->type != FT_CER && parent->type != FT_TA)
		return;
	ca = parent->obj;

	mft = find_child(parent, FT_MFT);
	if (!mft) {
		pr_debug("Need to create %s's Manifest", ca->rpp.caRepository);
		mft = create_missing_node(tree, ca->rpp.rpkiManifest, ca);
		mft->type = FT_MFT;
		mft->parent = parent; /* Needed by mft_new() */
		mft->obj = mft_new(mft);
		mft_generate_paths(mft->obj);
		rpkitree_add(tree, parent, mft);
	}

	if (find_child(parent, FT_CRL) == NULL) {
		pr_debug("Need to create %s's CRL", ca->rpp.caRepository);
		crl = create_missing_node(tree, ca->rpp.crldp, ca);
		crl->type = FT_CRL;
		crl->obj = crl_new(&crl->meta);
		crl_generate_paths(crl->obj);
		rpkitree_add(tree, parent, crl);

		mft_fix_filelist_crl(mft->obj, crl->meta.name);
	}
}

static void
apply_keyvals(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Applying keyvals: %s", node->meta.name);
	fields_apply_keyvals(node->meta.fields, &node->props);
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

static char *
utf8str2str(UTF8String_t *utf8str)
{
	return pstrndup((char *)(utf8str->buf), utf8str->size);
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
	char *snapshot_path;
	char *snapshot_uri;
	char *notif_path;

	HASH_ITER(hh, tree->notifications, notif, tmp) {
		if (STAILQ_EMPTY(&notif->snapshot.files))
			continue;

		pr_trace("- Notification: %s", notif->uri);

		if (notif->path.size == 0) {
			pr_err("%s does not match --rrdp-uri (%s), "
			    "so I cannot autocompute a path. "
			    "Please set it manually:\n"
			    "	[notification: %s]\n"
			    "	path = some/path/here.xml",
			    notif->uri, rrdp_uri, notif->uri);
			pr_warn("Skipping %s.", notif->uri);
			continue;
		}
		if (notif->snapshot.path.size == 0) {
			pr_err("%.*s does not match --rrdp-uri (%s), "
			    "so I cannot autocompute a path. "
			    "Please set it manually:\n"
			    "	[notification: %s]\n"
			    "	snapshot.path = some/path/here.xml",
			    (int)notif->snapshot.uri.size,
			    (char *)notif->snapshot.uri.buf,
			    rrdp_uri, notif->uri);
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

		snapshot_path = utf8str2str(&notif->snapshot.path);
		snapshot_uri = utf8str2str(&notif->snapshot.uri);
		notif_path = utf8str2str(&notif->path);

		rrdp_save_snapshot(snapshot_path, &SNAPSHOT, req, f);
		rrdp_save_notification(notif_path, snapshot_uri,
		    sha256_file_str(snapshot_path));

		free(notif_path);
		free(snapshot_uri);
		free(snapshot_path);

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

		printf("- URI: %s\n", node->meta.uri);
		printf("- path: %s\n", node->meta.path);

		switch (node->type) {
		case FT_TA:
		case FT_CER:
			cer_print_md(node->obj);
			break;
		case FT_CRL:
			crl_print_md(node->obj);
			break;
		case FT_MFT:
			mft_print_md(node->obj);
			break;
		case FT_ROA:
			roa_print_md(node->obj);
			break;
		default:
			pr_err("Unknown file type: %s", node->meta.name);
		}

		printf("\n");
		fields_print_md(node->meta.fields);

		printf("\n");
	}
}

static void
print_repository_csv(struct rpki_tree *tree)
{
	struct rpki_tree_node *node, *tmp1;
	struct rrdp_notification *notif, *tmp2;

	HASH_ITER(ghook, tree->nodes, node, tmp1) {
		switch (node->type) {
		case FT_TA:
		case FT_CER:
			cer_print_csv(node->obj);
			break;
		case FT_CRL:
			crl_print_csv(node->obj);
			break;
		case FT_MFT:
			mft_print_csv(node->obj);
			break;
		case FT_ROA:
			roa_print_csv(node->obj);
			break;
		default:
			pr_err("Unknown file type: %s", node->meta.name);
		}
	}

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
	pr_debug("Done.\n");

	pr_debug("Instancing generic RPKI objects...");
	rpkitree_pre_order(&tree, init_object, NULL);
	pr_debug("Done.\n");

	pr_debug("Generating default paths...");
	rpkitree_pre_order(&tree, generate_paths, NULL);
	pr_debug("Done.\n");

	pr_debug("Adding missing CRLs and Manifests...");
	rpkitree_pre_order(&tree, add_missing_objs, NULL);
	pr_debug("Done.\n");

	pr_debug("Applying keyvals...");
	rpkitree_pre_order(&tree, apply_keyvals, NULL);
	pr_debug("Done.\n");

	pr_debug("Post-processing (except manifests)...");
	rpkitree_pre_order(&tree, finish_not_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (except manifests)...");
	exec_mkdir_p(rsync_path, true);
	rpkitree_pre_order(&tree, write_not_mfts, NULL);
	// XXX assuming type cer
	tal_write(tree.root->obj, tal_path);
	pr_debug("Done.\n");

	pr_debug("Post-processing (manifests)...");
	rpkitree_pre_order(&tree, finish_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (manifests)...");
	rpkitree_pre_order(&tree, write_mfts, NULL);
	pr_debug("Done.\n");

	if (rrdp_uri && rrdp_path) {
		pr_debug("Writing RRDP XMLs...");
		write_rrdp(&tree);
		pr_debug("Done.\n");
	}

	if (print_format) {
		pr_debug("Printing objects...");
		print_repository(&tree);
		pr_debug("Done.\n");
	}

	return 0;
}
