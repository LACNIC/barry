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
#include "mft.h"
#include "print.h"
#include "roa.h"
#include "rpki_tree.h"
#include "str.h"
#include "tal.h"

char const *repo_descriptor = NULL;
char const *rsync_uri = "rsync://localhost:8873/rpki";
char const *rsync_path = "rsync/";
char const *tal_path = NULL;
Time_t default_now;
Time_t default_later;
GeneralizedTime_t default_gnow;
GeneralizedTime_t default_glater;
char const *keys_path;
bool print_objs = false;
unsigned int verbosity = 0;

#define OPTLONG_RSYNC_URI	"rsync-uri"
#define OPTLONG_RSYNC_PATH	"rsync-path"
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
		{ OPTLONG_TAL_PATH,   required_argument, 0, 't' },
		{ OPTLONG_NOW,        required_argument, 0, 'P' },
		{ OPTLONG_LATER,      required_argument, 0, 1026 },
		{ OPTLONG_KEYS,       required_argument, 0, 'k' },
		{ OPTLONG_PR_OBJS,    no_argument,       0, 'p' },
		{ OPTLONG_VERBOSE,    no_argument,       0, 'v' },
		{ OPTLONG_HELP,       no_argument,       0, 'h' },
		{ 0 }
	};
	int opt;
	char *optnow = NULL;
	char *optlater = NULL;

	while ((opt = getopt_long(argc, argv, "t:P:k:pvh", opts, NULL)) != -1) {
		switch (opt) {
		case 1024:
			rsync_uri = optarg;
			break;
		case 1025:
			rsync_path = optarg;
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
			print_objs = true;
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
	pr_debug("   --" OPTLONG_TAL_PATH "       (-t): %s", tal_path);
	pr_debug("   --" OPTLONG_NOW "            (-P): %s", optnow);
	pr_debug("   --" OPTLONG_LATER "              : %s", optlater);
	pr_debug("   --" OPTLONG_KEYS "               : %s", keys_path);
	pr_debug("   --" OPTLONG_PR_OBJS       "  (-p): %u", print_objs);
	pr_debug("   --" OPTLONG_VERBOSE "        (-v): %u", verbosity);
	pr_debug("");
}

static enum file_type
__infer_type(struct rpki_tree_node *node)
{
	size_t namelen;
	char *extension;

	if (node->type != FT_UNKNOWN)
		return node->type;

	namelen = strlen(node->name);
	if (namelen < 4)
		return FT_UNKNOWN;

	extension = node->name + strlen(node->name) - 4;

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

static enum file_type
infer_type(struct rpki_tree_node *node)
{
	node->type = __infer_type(node);
	return node->type;
}

static struct rpki_tree_node *
find_child(struct rpki_tree_node *parent, enum file_type type)
{
	struct rpki_tree_node *child, *tmp;

	HASH_ITER(phook, parent->children, child, tmp)
		if (infer_type(child) == type)
			return child;

	return NULL;
}

static void
add_missing_objs(struct rpki_tree *tree, struct rpki_tree_node *parent,
    void *arg)
{
	struct rpki_tree_node *child;
	struct rpki_certificate *ca;
	char *slash;

	if (parent->type != FT_CER && parent->type != FT_TA)
		return;
	ca = parent->obj;

	if (find_child(parent, FT_MFT) == NULL) {
		pr_debug("Need to create %s's Manifest", ca->rpp.caRepository);
		child = pzalloc(sizeof(struct rpki_tree_node));
		slash = strrchr(ca->rpp.rpkiManifest, '/');
		child->name = slash ? (slash + 1) : ca->rpp.rpkiManifest;
		child->type = FT_MFT;
		child->obj = mft_new(child->name, ca);
		mft_generate_paths(child->obj, child->name);
		child->parent = parent;
		rpkitree_add(tree, parent, child);
	}

	if (find_child(parent, FT_CRL) == NULL) {
		pr_debug("Need to create %s's CRL", ca->rpp.caRepository);
		child = pzalloc(sizeof(struct rpki_tree_node));
		slash = strrchr(ca->rpp.crldp, '/');
		child->name = slash ? (slash + 1) : ca->rpp.crldp;
		child->type = FT_CRL;
		child->obj = crl_new(ca);
		crl_generate_paths(child->obj, child->name);
		child->parent = parent;
		rpkitree_add(tree, parent, child);
	}
}

static struct rpki_certificate *
get_parent(struct rpki_tree_node *node)
{
	struct rpki_tree_node *parent;

	parent = node->parent;
	if (parent == NULL)
		return NULL;
	if (parent->type == FT_TA || parent->type == FT_CER)
		return parent->obj;

	panic("%s's parent is not a certificate.", node->name);
}

static void
init_object(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Initializing: %s", node->name);

	switch (infer_type(node)) {
	case FT_TA:
	case FT_CER:
		node->obj = cer_new(node->name, get_parent(node));
		break;
	case FT_CRL:
		node->obj = crl_new(get_parent(node));
		break;
	case FT_MFT:
		node->obj = mft_new(node->name, get_parent(node));
		break;
	case FT_ROA:
		node->obj = roa_new(node->name, get_parent(node));
		break;
	default:
		panic("Unknown file type: %s", node->name);
	}
}

static void
generate_paths(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Generating paths: %s", node->name);

	switch (infer_type(node)) {
	case FT_TA:
	case FT_CER:
		cer_generate_paths(node->obj, node->name);
		break;
	case FT_CRL:
		crl_generate_paths(node->obj, node->name);
		break;
	case FT_MFT:
		mft_generate_paths(node->obj, node->name);
		break;
	case FT_ROA:
		roa_generate_paths(node->obj, node->name);
		break;
	default:
		panic("Unknown file type: %s", node->name);
	}
}

static void
apply_keyvals(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Applying keyvals: %s", node->name);

	switch (infer_type(node)) {
	case FT_TA:
	case FT_CER:
		cer_apply_keyvals(node->obj, &node->props);
		break;
	case FT_CRL:
		crl_apply_keyvals(node->obj, &node->props);
		break;
	case FT_MFT:
		mft_apply_keyvals(node->obj, &node->props);
		break;
	case FT_ROA:
		roa_apply_keyvals(node->obj, &node->props);
		break;
	default:
		panic("Unknown file type: %s", node->name);
	}
}

static void
finish_not_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Finishing (unless it's a manifest): %s", node->name);

	switch (infer_type(node)) {
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
		panic("Unknown file type: %s", node->name);
	}
}

static void
finish_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	if (infer_type(node) != FT_MFT)
		return;

	pr_debug("Finishing: %s", node->name);
	mft_finish(node->obj, node->parent->children);
}

static void
write_not_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	pr_debug("Writing file (unless it's a manifest): %s", node->name);

	switch (infer_type(node)) {
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
		panic("Unknown file type: %s", node->name);
	}
}

static void
write_mfts(struct rpki_tree *tree, struct rpki_tree_node *node, void *arg)
{
	if (infer_type(node) != FT_MFT)
		return;

	pr_debug("Writing: %s", node->name);
	mft_write(node->obj);
}

static void
print_repository(struct rpki_tree *tree)
{
	struct rpki_tree_node *node, *tmp;

	printf("# Tree\n\n");
	printf("```\n");
	rpkitree_print(tree);
	printf("```\n\n");

	printf("# Files\n\n");
	HASH_ITER(ghook, tree->nodes, node, tmp) {
		printf("## %s\n\n", node->name);

		switch (infer_type(node)) {
		case FT_TA:
		case FT_CER:
			cer_print(node->obj);
			break;
		case FT_CRL:
			crl_print(node->obj);
			break;
		case FT_MFT:
			mft_print(node->obj);
			break;
		case FT_ROA:
			roa_print(node->obj);
			break;
		default:
			panic("Unknown file type: %s", node->name);
		}

		printf("\n");
	}
}

int
main(int argc, char **argv)
{
	struct rpki_tree tree;

	/* register_signal_handlers(); TODO */

	parse_options(argc, argv);

	tree = rpkitree_load(repo_descriptor);

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

	if (print_objs) {
		pr_debug("Printing objects...");
		print_repository(&tree);
		pr_debug("Done.\n");
	}

	return 0;
}
