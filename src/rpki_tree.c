#include "rpki_tree.h"

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

static char *
tokenize(bool (*chr_matches)(char))
{
	struct dynamic_string result = { 0 };
	size_t i;

	do {
		for (i = reader.offset; i < reader.size; i++) {
			if (!chr_matches(reader.buf[i])) {
				dstr_append(&result,
				    reader.buf + reader.offset,
				    i - reader.offset);
				dstr_append(&result, (unsigned char *)"", 1);
				reader.offset = i;
				return result.buf;
			}
		}

		dstr_append(&result,
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

void
rpkitree_pre_order(
    struct rpki_tree_node *root,
    void (*cb)(struct rpki_tree_node *, void *),
    void *arg
) {
	struct rpki_tree_node *child, *tmp;

	if (root == NULL)
		return;
	cb(root, arg);

	// TODO ditch recursion
	HASH_ITER(phook, root->children, child, tmp)
		rpkitree_pre_order(child, cb, arg);
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
