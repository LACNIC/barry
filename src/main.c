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
#include "tal.h"

static unsigned int line = 1;

#define BADCFG(fmt, ...) panic("Line %u: " fmt, line, ##__VA_ARGS__)

struct file_reader {
	int fd;
	unsigned char buf[4096];
	size_t offset;
	size_t size;
} reader;

enum token_type {
	TKNT_STR,
	TKNT_ASSIGNMENT = '=',
	TKNT_START = '[',
	TKNT_END = ']',
	TKNT_SEPARATOR = ',',
	TKNT_EOF,
};

static struct rpki_tree_node *nodes;
static struct rpki_tree_node *root;

char const *repo_descriptor = NULL;
char const *rsync_uri = "rsync://localhost:8873/rpki";
char const *rsync_path = "rsync/";
char const *tal_path = NULL;
Time_t default_now;
Time_t default_later;
GeneralizedTime_t default_gnow;
GeneralizedTime_t default_glater;
bool print_objs = false;
unsigned int verbosity = 0;

#define OPTLONG_RSYNC_URI	"rsync-uri"
#define OPTLONG_RSYNC_PATH	"rsync-path"
#define OPTLONG_TAL_PATH	"tal-path"
#define OPTLONG_NOW		"now"
#define OPTLONG_LATER		"later"
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
		{ OPTLONG_NOW,        required_argument, 0, 'n' },
		{ OPTLONG_LATER,      required_argument, 0, 1026 },
		{ OPTLONG_PR_OBJS,    no_argument,       0, 'p' },
		{ OPTLONG_VERBOSE,    no_argument,       0, 'v' },
		{ OPTLONG_HELP,       no_argument,       0, 'h' },
		{ 0 }
	};
	int opt;
	char *optnow = NULL;
	char *optlater = NULL;

	while ((opt = getopt_long(argc, argv, "t:n:pvh", opts, NULL)) != -1) {
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
		case 'n':
			optnow = optarg;
			break;
		case 1026:
			optlater = optarg;
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
	pr_debug("   --" OPTLONG_NOW "            (-n): %s", optnow);
	pr_debug("   --" OPTLONG_LATER "              : %s", optlater);
	pr_debug("   --" OPTLONG_PR_OBJS       "  (-p): %u", print_objs);
	pr_debug("   --" OPTLONG_VERBOSE "        (-v): %u", verbosity);
	pr_debug("");
}

static struct rpki_tree_node *
find_node(char const *name)
{
	struct rpki_tree_node *node;
	size_t keylen;

	keylen = strlen(name);
	HASH_FIND(ghook, nodes, name, keylen, node);

	return node;
}

static void
__add_node(struct rpki_tree_node *node)
{
	size_t keylen = strlen(node->name);
	HASH_ADD_KEYPTR(ghook, nodes, node->name, keylen, node);
}

static void
add_node(struct rpki_tree_node *node)
{
	if (find_node(node->name) != NULL)
		panic("There is more than one node named '%s'.", node->name);
	__add_node(node);
}

static void
add_child(struct rpki_tree_node *parent, struct rpki_tree_node *child)
{
	size_t keylen = strlen(child->name);
	HASH_ADD_KEYPTR(phook, parent->children, child->name, keylen, child);
	child->parent = parent;
}

static bool
is_alphanumeric(char chr)
{
	return ('a' <= chr && chr <= 'z')
	    || ('A' <= chr && chr <= 'Z')
	    || ('0' <= chr && chr <= '9');
}

static bool
refresh_reader(void)
{
	ssize_t bytes;

	if (reader.fd == -1)
		return false;

	bytes = read(reader.fd, reader.buf, sizeof(reader.buf));
	if (bytes < 0)
		panic("%s: %s", repo_descriptor, strerror(errno));
	if (bytes == 0) {
		if (reader.fd != STDIN_FILENO)
			close(reader.fd);
		reader.fd = -1;
		return false;
	}

	reader.offset = 0;
	reader.size = bytes;
	return true;
}

static unsigned char *
next_char(void)
{
	if (reader.offset >= reader.size && !refresh_reader())
		return NULL;

	/* pr_trace("	Character '%c'", reader.buf[reader.offset]); */
	return reader.buf + reader.offset++;
}

static size_t
next_power_of_2(size_t src)
{
	size_t power = 1;
	while (power < src)
		power <<= 1;
	return power;
}

struct dynamic_string {
	char *buf;
	size_t len;
	size_t size;
};

static void
grow_string(struct dynamic_string *str, unsigned char *addend, size_t addlen)
{
	size_t total;

	total = str->len + addlen;
	if (total > str->size) {
		str->size = next_power_of_2(total);
		str->buf = realloc(str->buf, str->size);
		if (!str->buf)
			enomem;
	}

	memcpy(str->buf + str->len, addend, addlen);
	str->len += addlen;
}

static char *
tokenize(bool (*chr_matches)(char))
{
	struct dynamic_string result = { 0 };
	size_t i;

	do {
		for (i = reader.offset; i < reader.size; i++) {
			if (!chr_matches(reader.buf[i])) {
				grow_string(&result,
				    reader.buf + reader.offset,
				    i - reader.offset);
				grow_string(&result, (unsigned char *)"", 1);
				reader.offset = i;
				return result.buf;
			}
		}

		grow_string(&result,
		    reader.buf + reader.offset,
		    i - reader.offset);

		// TODO If ID is EOF, this triggers
		if (!refresh_reader())
			BADCFG("Unterminated token at the end of file");
	} while (true);
}

static unsigned char *
skip_until(unsigned char delim)
{
	unsigned char *chr;

	do {
		chr = next_char();
		if (chr == NULL)
			return NULL;
	} while (*chr != delim);

	return chr;
}

static char const *
tknt2str(enum token_type type)
{
	switch (type) {
	case TKNT_STR:
		return "String";
	case TKNT_ASSIGNMENT:
		return "=";
	case TKNT_START:
		return "[";
	case TKNT_END:
		return "]";
	case TKNT_SEPARATOR:
		return ",";
	case TKNT_EOF:
		return "EOF";
	}

	return "Unknown";
}

static bool
is_unquoted_string_chr(char chr)
{
	return chr != ' '
	    && chr != '\t'
	    && chr != '\n'
	    && chr != TKNT_ASSIGNMENT
	    && chr != TKNT_START
	    && chr != TKNT_END
	    && chr != TKNT_SEPARATOR;
}

static bool
is_quoted_string_chr(char chr)
{
	return chr != '"';
}

static enum token_type
next_token(char **tkn)
{
	unsigned char *_chr, chr;

	*tkn = NULL;

	do {
		_chr = next_char();
		if (_chr == NULL) {
			pr_trace("Token: EOF1");
			*tkn = "EOF";
			return TKNT_EOF;
		}
		chr = *_chr;

		if (is_alphanumeric(chr)) {
			reader.offset--;
			*tkn = tokenize(is_unquoted_string_chr);
			pr_trace("Token: %s", *tkn);
			return TKNT_STR;
		}

		switch (chr) {
		case '#': /* Comment */
			if (!skip_until('\n')) {
				pr_trace("Token: EOF2");
				*tkn = "EOF";
				return TKNT_EOF;
			}
			/* No break */
		case '\n':
			line++;
			/* No break */
		case ' ':
		case '\t':
			break;

		case '"':
			*tkn = tokenize(is_quoted_string_chr);
			pr_trace("Token String: \"%s\"", *tkn);
			reader.offset++;
			return TKNT_STR;

		case TKNT_ASSIGNMENT:
			*tkn = "=";
			pr_trace("Token %c", chr);
			return chr;

		case TKNT_START:
			*tkn = "[";
			pr_trace("Token %c", chr);
			return chr;

		case TKNT_END:
			*tkn = "]";
			pr_trace("Token %c", chr);
			return chr;

		case TKNT_SEPARATOR:
			*tkn = ",";
			pr_trace("Token %c", chr);
			return chr;

		default:
			BADCFG("Unexpected character: %c (0x%x)", chr, chr);
		}
	} while (true);
}

static char *
expect_token(enum token_type expected)
{
	enum token_type actual;
	char *token;

	actual = next_token(&token);
	if (expected != actual)
		BADCFG("Expected %s, got %s '%s'",
		    tknt2str(expected), tknt2str(actual),
		    token);

	return token;
}

static struct kv_value
accept_value(char const *key)
{
	char *token;
	struct kv_value value;
	struct kv_node *node;

	switch (next_token(&token)) {
	case TKNT_STR:
		value.type = VALT_STR;
		value.v.str = token;
		break;

	case TKNT_START:
		value.type = VALT_ARRAY;
		STAILQ_INIT(&value.v.list);

list_next:	switch (next_token(&token)) {
		case TKNT_STR:
			node = pzalloc(sizeof(struct kv_node));
			node->value = token;
			STAILQ_INSERT_TAIL(&value.v.list, node, hook);

			switch (next_token(&token)) {
			case TKNT_SEPARATOR:
				goto list_next;
			case TKNT_END:
				goto list_end;
			default:
				BADCFG("Don't know what to do with '%s' "
				    "while parsing array '%s'.",
				    token, key);
			}

		case TKNT_END:
list_end:		break;

		default:
			BADCFG("Don't know what to do with '%s' "
			    "while parsing array '%s'.",
			    token, key);
		}
		break;

	default:
		BADCFG("Don't know what to do with token '%s'.", token);
		memset(&value, 0, sizeof(value));
	}

	return value;
}

static void
read_keyvals(void)
{
	char *tkn;
	char *filename;
	struct rpki_tree_node *file;
	struct keyval *kv;

	do {
		switch (next_token(&tkn)) {
		case TKNT_START:
			filename = expect_token(TKNT_STR);
			file = find_node(filename);
			if (file == NULL)
				BADCFG("The tree does not declare file '%s'",
				    filename);
			expect_token(TKNT_END);
			break;

		case TKNT_STR:
			kv = pzalloc(sizeof(struct keyval));
			kv->key = tkn;
			expect_token(TKNT_ASSIGNMENT);
			kv->val = accept_value(kv->key);
			STAILQ_INSERT_TAIL(&file->props, kv, hook);
			break;

		case TKNT_EOF:
			pr_trace("EOF.");
			return;

		default:
			BADCFG("Unexpected keyval token: %s", tkn);
		}
	} while (true);
}

static unsigned int
count_indentation(void)
{
	unsigned int indent;
	unsigned char *chr;

	indent = 0;

	do {
		chr = next_char();
		if (!chr)
			return indent;

		switch (*chr) {
		case ' ':
			indent++;
			break;
		case '\t':
			indent = (indent & ~7u) + 8;
			break;
		case '#':
			if (!skip_until('\n'))
				return indent;
			/* No break */
		case '\n':
			line++;
			indent = 0;
			break;
		default:
			reader.offset--;
			return indent;
		}
	} while (true);
}

static void
read_tree(void)
{
	unsigned int indent;
	char *token;

	struct rpki_tree_node *last;
	struct rpki_tree_node *current;

	refresh_reader();

	root = last = NULL;
	do {
		indent = count_indentation();

		switch (next_token(&token)) {
		case TKNT_START:
			reader.offset--;
			return;

		case TKNT_STR:
			current = pzalloc(sizeof(struct rpki_tree_node));
			current->name = token;
			current->indent = indent;
			STAILQ_INIT(&current->props);

			add_node(current);

			if (root == NULL) {
				root = last = current;

			} else if (current->indent > last->indent) {
				add_child(last, current);
				last = current;

			} else if (current->indent == last->indent) {
sibling:			if (last->parent == NULL)
					BADCFG("'%s' is disconnected from the tree.",
					    current->name);
				add_child(last->parent, current);
				last = current;

			} else {
				for (last = last->parent; last != NULL; last = last->parent)
					if (current->indent == last->indent)
						goto sibling;
				BADCFG("Node '%s' seems misaligned; "
				    "please review its indentation.",
				    current->name);
			}
			break;

		case TKNT_EOF:
			return;

		default:
			BADCFG("Unexpected tree token: %s", token);
		}
	} while (true);
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
add_missing_objs(struct rpki_tree_node *parent, void *arg)
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
		__add_node(child);
		add_child(parent, child);
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
		__add_node(child);
		add_child(parent, child);
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
init_object(struct rpki_tree_node *node, void *arg)
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
		BADCFG("Unknown file type: %s", node->name);
	}
}

static void
generate_paths(struct rpki_tree_node *node, void *arg)
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
		BADCFG("Unknown file type: %s", node->name);
	}
}

static void
apply_keyvals(struct rpki_tree_node *node, void *arg)
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
		BADCFG("Unknown file type: %s", node->name);
	}
}

static void
finish_not_mfts(struct rpki_tree_node *node, void *arg)
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
		BADCFG("Unknown file type: %s", node->name);
	}
}

static void
finish_mfts(struct rpki_tree_node *node, void *arg)
{
	if (infer_type(node) != FT_MFT)
		return;

	pr_debug("Finishing: %s", node->name);
	mft_finish(node->obj, node->parent->children);
}

static void
write_not_mfts(struct rpki_tree_node *node, void *arg)
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
		BADCFG("Unknown file type: %s", node->name);
	}
}

static void
write_mfts(struct rpki_tree_node *node, void *arg)
{
	if (infer_type(node) != FT_MFT)
		return;

	pr_debug("Writing: %s", node->name);
	mft_write(node->obj);
}

static void
print_node(struct rpki_tree_node *node, unsigned int indent)
{
	struct rpki_tree_node *child, *tmp;
	size_t i;

	for (i = 0; i < indent; i++)
		printf("\t");
	printf("%s\n", node->name);

	indent++;
	HASH_ITER(phook, node->children, child, tmp)
		print_node(child, indent);
}

static void
print_repository(void)
{
	struct rpki_tree_node *node, *tmp;

	printf("# Tree\n\n");
	printf("```\n");
	print_node(root, 0);
	printf("```\n\n");

	printf("# Files\n\n");
	HASH_ITER(ghook, nodes, node, tmp) {
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
			BADCFG("Unknown file type: %s", node->name);
		}

		printf("\n");
	}
}

int
main(int argc, char **argv)
{
	/* register_signal_handlers(); TODO */

	parse_options(argc, argv);

	if (strcmp(repo_descriptor, "-") != 0) {
		reader.fd = open(repo_descriptor, O_RDONLY, 0);
		if (reader.fd < 0)
			BADCFG("%s: %s", repo_descriptor, strerror(errno));
	} else {
		reader.fd = STDIN_FILENO;
	}

	pr_debug("Reading tree from input...");
	read_tree();
	pr_debug("Done.\n");

	pr_debug("Reading keyvals from input...");
	read_keyvals();
	pr_debug("Done.\n");

	pr_debug("Instancing generic RPKI objects...");
	rpkitree_pre_order(root, init_object, NULL);
	pr_debug("Done.\n");

	pr_debug("Generating default paths...");
	rpkitree_pre_order(root, generate_paths, NULL);
	pr_debug("Done.\n");

	pr_debug("Adding missing CRLs and Manifests...");
	rpkitree_pre_order(root, add_missing_objs, NULL);
	pr_debug("Done.\n");

	pr_debug("Applying keyvals...");
	rpkitree_pre_order(root, apply_keyvals, NULL);
	pr_debug("Done.\n");

	pr_debug("Post-processing (except manifests)...");
	rpkitree_pre_order(root, finish_not_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (except manifests)...");
	exec_mkdir_p(rsync_path, true);
	rpkitree_pre_order(root, write_not_mfts, NULL);
	// XXX assuming type cer
	tal_write(root->obj, tal_path);
	pr_debug("Done.\n");

	pr_debug("Post-processing (manifests)...");
	rpkitree_pre_order(root, finish_mfts, NULL);
	pr_debug("Done.\n");

	pr_debug("Writing files (manifests)...");
	rpkitree_pre_order(root, write_mfts, NULL);
	pr_debug("Done.\n");

	if (print_objs) {
		pr_debug("Printing objects...");
		print_repository();
		pr_debug("Done.\n");
	}

	return 0;
}
