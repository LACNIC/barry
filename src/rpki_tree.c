#include "rpki_tree.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "alloc.h"
#include "print.h"
#include "str.h"

#define BADCFG(rdr, fmt, ...) panic("Line %u: " fmt, rdr->line, ##__VA_ARGS__)
#define UNEXPECTED_TOKEN(rdr, tkn) BADCFG(rdr, "Unexpected token: %s", tkn)

struct rd_parse_context {
	/* File descriptor for reading into @buf */
	int fd;
	/* Path to the file from where we opened the file descriptor */
	char const *path;
	/* Current line number, to report during errors */
	unsigned int line;

	unsigned char buf[4096];
	/* Number of bytes we've already consumed from @buf */
	size_t offset;
	/* Total meaningful bytes in @buf, since buf[0] */
	size_t size;

	struct rpki_tree result;
};

enum token_type {
	TKNT_STR,
	TKNT_ASSIGNMENT = '=',
	TKNT_SET_START = '[',
	TKNT_SET_END = ']',
	TKNT_MAP_START = '{',
	TKNT_MAP_END = '}',
	TKNT_SEPARATOR = ',',
	TKNT_EOF,
};

static struct rpki_tree_node *
find_node(struct rd_parse_context *ctx, char const *name)
{
	struct rpki_tree_node *node;
	size_t keylen;

	keylen = strlen(name);
	HASH_FIND(ghook, ctx->result.nodes, name, keylen, node);

	return node;
}

static void
__add_node(struct rpki_tree *tree, struct rpki_tree_node *node)
{
	size_t keylen = strlen(node->meta.name);
	HASH_ADD_KEYPTR(ghook, tree->nodes, node->meta.name, keylen, node);
}

static void
add_node(struct rd_parse_context *ctx, struct rpki_tree_node *node)
{
	if (find_node(ctx, node->meta.name) != NULL)
		panic("There is more than one node named '%s'.", node->meta.name);
	__add_node(&ctx->result, node);
}

static void
add_child(struct rpki_tree_node *parent, struct rpki_tree_node *child)
{
	size_t keylen = strlen(child->meta.name);
	HASH_ADD_KEYPTR(phook, parent->children, child->meta.name, keylen, child);
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
refresh_reader(struct rd_parse_context *ctx)
{
	ssize_t bytes;

	if (ctx->fd == -1)
		return false;

	bytes = read(ctx->fd, ctx->buf, sizeof(ctx->buf));
	if (bytes < 0)
		panic("%s: %s", ctx->path, strerror(errno));
	if (bytes == 0) {
		if (ctx->fd != STDIN_FILENO)
			close(ctx->fd);
		ctx->fd = -1;
		return false;
	}

	ctx->offset = 0;
	ctx->size = bytes;
	return true;
}

static unsigned char *
next_char(struct rd_parse_context *ctx)
{
	if (ctx->offset >= ctx->size && !refresh_reader(ctx))
		return NULL;

	/* pr_trace("	Character '%c'", reader.buf[reader.offset]); */
	return ctx->buf + ctx->offset++;
}

static char *
tokenize(struct rd_parse_context *ctx, bool (*chr_matches)(char))
{
	struct dynamic_string result = { 0 };
	size_t i;

	do {
		for (i = ctx->offset; i < ctx->size; i++) {
			if (!chr_matches(ctx->buf[i])) {
				dstr_append(&result, "%.*s",
				    (int)(i - ctx->offset),
				    ctx->buf + ctx->offset);
				goto commit;
			}
		}

		dstr_append(&result, "%.*s",
		    (int)(i - ctx->offset),
		    ctx->buf + ctx->offset);

		if (!refresh_reader(ctx)) {
			if (result.buf == NULL)
				return NULL;
			goto commit;
		}
	} while (true);

commit:
	dstr_finish(&result);
	ctx->offset = i;
	return result.buf;
}

static unsigned char *
skip_until(struct rd_parse_context *ctx, unsigned char delim)
{
	unsigned char *chr;

	do {
		chr = next_char(ctx);
		if (chr == NULL)
			return NULL;
	} while (*chr != delim);

	return chr;
}

static char const *
tknt2str(enum token_type type)
{
	switch (type) {
	case TKNT_STR:		return "String";
	case TKNT_ASSIGNMENT:	return "=";
	case TKNT_SET_START:	return "[";
	case TKNT_SET_END:	return "]";
	case TKNT_MAP_START:	return "{";
	case TKNT_MAP_END:	return "}";
	case TKNT_SEPARATOR:	return ",";
	case TKNT_EOF:		return "EOF";
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
	    && chr != TKNT_SET_START
	    && chr != TKNT_SET_END
	    && chr != TKNT_MAP_START
	    && chr != TKNT_MAP_END
	    && chr != TKNT_SEPARATOR;
}

static bool
is_quoted_string_chr(char chr)
{
	return chr != '"';
}

struct token {
	enum token_type type;
	char *str;
};

static enum token_type
init_token(struct token *tkn, enum token_type type, char *str)
{
	tkn->type = type;
	tkn->str = str;
	pr_trace("Token: %s", str);
	return type;
}

static enum token_type
next_token(struct rd_parse_context *ctx, struct token *tkn)
{
	unsigned char *_chr, chr;
	char *token;

	do {
		_chr = next_char(ctx);
		if (_chr == NULL)
			return init_token(tkn, TKNT_EOF, "EOF");
		chr = *_chr;

		if (is_alphanumeric(chr)) {
			ctx->offset--;

			token = tokenize(ctx, is_unquoted_string_chr);
			return token
			    ? init_token(tkn, TKNT_STR, token)
			    : init_token(tkn, TKNT_EOF, "EOF");
		}

		switch (chr) {
		case '#': /* Comment */
			if (!skip_until(ctx, '\n'))
				return init_token(tkn, TKNT_EOF, "EOF");
			/* No break */
		case '\n':
			ctx->line++;
			/* No break */
		case ' ':
		case '\t':
			break;

		case '"':
			init_token(tkn, TKNT_STR,
			    tokenize(ctx, is_quoted_string_chr));
			ctx->offset++;
			return tkn->type;

		case TKNT_ASSIGNMENT:
			return init_token(tkn, TKNT_ASSIGNMENT, "=");

		case TKNT_SET_START:
			return init_token(tkn, TKNT_SET_START, "[");

		case TKNT_SET_END:
			return init_token(tkn, TKNT_SET_END, "]");

		case TKNT_MAP_START:
			return init_token(tkn, TKNT_MAP_START, "{");

		case TKNT_MAP_END:
			return init_token(tkn, TKNT_MAP_END, "}");

		case TKNT_SEPARATOR:
			return init_token(tkn, TKNT_SEPARATOR, ",");

		default:
			BADCFG(ctx, "Unexpected character: %c (0x%x)", chr, chr);
		}
	} while (true);
}

static char *
expect_token(struct rd_parse_context *ctx, enum token_type expected)
{
	struct token tkn;

	if (expected != next_token(ctx, &tkn))
		BADCFG(ctx, "Expected %s, got %s '%s'", tknt2str(expected),
		    tknt2str(tkn.type), tkn.str);

	return tkn.str;
}

static struct kv_value
accept_value(struct rd_parse_context *ctx, struct token *peek)
{
	struct token tkn;
	struct kv_value result;
	struct kv_node *node;
	struct keyval *kv;

	if (peek)
		tkn = *peek;
	else
		next_token(ctx, &tkn);

	switch (tkn.type) {
	case TKNT_STR:
		result.type = VALT_STR;
		result.v.str = tkn.str;
		break;

	case TKNT_SET_START:
		result.type = VALT_SET;
		STAILQ_INIT(&result.v.set);

		do {
			switch (next_token(ctx, &tkn)) {
			case TKNT_STR:
			case TKNT_SET_START:
			case TKNT_MAP_START:
				node = pzalloc(sizeof(struct kv_node));
				node->value = accept_value(ctx, &tkn);
				STAILQ_INSERT_TAIL(&result.v.set, node, hook);

				switch (next_token(ctx, &tkn)) {
				case TKNT_SET_END:
					return result;
				case TKNT_SEPARATOR:
					break;
				default:
					UNEXPECTED_TOKEN(ctx, tkn.str);
				}

				break;
			case TKNT_SET_END:
				return result;
			default:
				UNEXPECTED_TOKEN(ctx, tkn.str);
			}
		} while (true);

	case TKNT_MAP_START:
		result.type = VALT_MAP;
		STAILQ_INIT(&result.v.map);

		do {
			switch (next_token(ctx, &tkn)) {
			case TKNT_STR:
				kv = pzalloc(sizeof(struct keyval));
				kv->key = tkn.str;
				expect_token(ctx, TKNT_ASSIGNMENT);
				kv->value = accept_value(ctx, NULL);
				STAILQ_INSERT_TAIL(&result.v.map, kv, hook);

				switch (next_token(ctx, &tkn)) {
				case TKNT_MAP_END:
					return result;
				case TKNT_SEPARATOR:
					break;
				default:
					UNEXPECTED_TOKEN(ctx, tkn.str);
				}

				break;
			case TKNT_MAP_END:
				return result;
			default:
				UNEXPECTED_TOKEN(ctx, tkn.str);
			}
		} while (true);

	default:
		UNEXPECTED_TOKEN(ctx, tkn.str);
		memset(&result, 0, sizeof(result));
	}

	return result;
}

static void
read_keyvals(struct rd_parse_context *ctx)
{
	struct token tkn;
	char *filename;
	struct rpki_tree_node *file;
	struct keyval *kv;

	do {
		switch (next_token(ctx, &tkn)) {
		case TKNT_SET_START:
			filename = expect_token(ctx, TKNT_STR);
			file = find_node(ctx, filename);
			if (file == NULL)
				BADCFG(ctx,
				    "The tree does not declare file '%s'",
				    filename);
			expect_token(ctx, TKNT_SET_END);
			break;

		case TKNT_STR:
			kv = pzalloc(sizeof(struct keyval));
			kv->key = tkn.str;
			expect_token(ctx, TKNT_ASSIGNMENT);
			kv->value = accept_value(ctx, NULL);
			STAILQ_INSERT_TAIL(&file->props, kv, hook);
			break;

		case TKNT_EOF:
			pr_trace("EOF.");
			return;

		default:
			BADCFG(ctx, "Unexpected keyval token: %s", tkn.str);
		}
	} while (true);
}

static unsigned int
count_indentation(struct rd_parse_context *ctx)
{
	unsigned int indent;
	unsigned char *chr;

	indent = 0;

	do {
		chr = next_char(ctx);
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
			if (!skip_until(ctx, '\n'))
				return indent;
			/* No break */
		case '\n':
			ctx->line++;
			indent = 0;
			break;
		default:
			ctx->offset--;
			return indent;
		}
	} while (true);
}

static void
read_tree(struct rd_parse_context *ctx)
{
	unsigned int indent;
	struct token tkn;

	struct rpki_tree_node *last;
	struct rpki_tree_node *current;

	refresh_reader(ctx);

	ctx->result.root = last = NULL;
	do {
		indent = count_indentation(ctx);

		switch (next_token(ctx, &tkn)) {
		case TKNT_STR:
			current = pzalloc(sizeof(struct rpki_tree_node));
			current->meta.name = tkn.str;
			current->meta.fields = pzalloc(sizeof(struct field));
			current->indent = indent;
			STAILQ_INIT(&current->props);

			add_node(ctx, current);

			if (ctx->result.root == NULL) {
				ctx->result.root = last = current;

			} else if (current->indent > last->indent) {
				add_child(last, current);
				last = current;

			} else if (current->indent == last->indent) {
sibling:			if (last->parent == NULL)
					BADCFG(ctx,
					    "'%s' is disconnected from the tree.",
					    current->meta.name);
				add_child(last->parent, current);
				last = current;

			} else {
				for (last = last->parent; last != NULL; last = last->parent)
					if (current->indent == last->indent)
						goto sibling;
				BADCFG(ctx, "Node '%s' seems misaligned; "
				    "please review its indentation.",
				    current->meta.name);
			}
			break;

		case TKNT_SET_START:
			ctx->offset--;
			/* No break */
		case TKNT_EOF:
			return;
		default:
			BADCFG(ctx, "Unexpected tree token: %s", tkn.str);
		}
	} while (true);
}

struct rpki_tree
rpkitree_load(char const *rd_path)
{
	struct rd_parse_context ctx = { 0 };

	if (strcmp(rd_path, "-") != 0) {
		ctx.fd = open(rd_path, O_RDONLY, 0);
		if (ctx.fd < 0)
			panic("%s: %s", rd_path, strerror(errno));
	} else {
		ctx.fd = STDIN_FILENO;
	}

	ctx.path = rd_path;
	ctx.line = 1;

	pr_debug("Reading tree from input...");
	read_tree(&ctx);
	pr_debug("Done.\n");

	pr_debug("Reading keyvals from input...");
	read_keyvals(&ctx);
	pr_debug("Done.\n");

	return ctx.result;
}

static void
__preorder(
    struct rpki_tree *tree,
    struct rpki_tree_node *node,
    void (*cb)(struct rpki_tree *, struct rpki_tree_node *, void *),
    void *arg
) {
	struct rpki_tree_node *child, *tmp;

	cb(tree, node, arg);

	// TODO ditch recursion
	HASH_ITER(phook, node->children, child, tmp)
		__preorder(tree, child, cb, arg);
}

void
rpkitree_pre_order(
    struct rpki_tree *tree,
    void (*cb)(struct rpki_tree *, struct rpki_tree_node *, void *),
    void *arg
) {
	if (tree != NULL && tree->root != NULL)
		__preorder(tree, tree->root, cb, arg);
}

void
rpkitree_add(struct rpki_tree *tree, struct rpki_tree_node *parent,
    struct rpki_tree_node *child)
{
	__add_node(tree, child);
	add_child(parent, child);
}

static void
print_node(struct rpki_tree_node *node, unsigned int indent)
{
	struct rpki_tree_node *child, *tmp;
	size_t i;

	for (i = 0; i < indent; i++)
		printf("\t");
	printf("%s\n", node->meta.name);

	indent++;
	HASH_ITER(phook, node->children, child, tmp)
		print_node(child, indent);
}

void
rpkitree_print(struct rpki_tree *tree)
{
	print_node(tree->root, 0);
}
