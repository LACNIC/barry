#include "../src/rpki_tree.c"

#include <check.h>
#include <stdarg.h>
#include <unistd.h>

#define RDFD 0
#define WRFD 1

/* Mocks */

char const *rrdp_uri = "https://localhost:8443/rpki";
char const *rrdp_path = "rrdp/";
unsigned int verbosity = 2;

struct field *
field_add(struct field *parent, char const *name,
    struct field_type const *type, void *address, size_t size)
{
	ck_abort_msg("%s() called!", __func__);
}

/* Tests */

static void
send_input(int fd, char *input)
{
	ck_assert_int_gt(write(fd, input, strlen(input)), 0);
}

#define ck_value_str(_value, actual) do {			\
		ck_assert_int_eq(VALT_STR, actual.type);	\
		ck_assert_str_eq(_value, actual.v.str);		\
	} while (0);


#define ck_keyval_str(_key, _value, actual) do {		\
		ck_assert_str_eq(_key, actual->key);		\
		ck_assert_int_eq(VALT_STR, actual->value.type);	\
		ck_assert_str_eq(_value, actual->value.v.str);	\
	} while (0);

START_TEST(check_accept_value)
{
	int fds[2];
	struct rd_parse_context ctx;
	struct kv_value value;
	struct kv_node *node, *subnode;
	struct keyval *kv, *subkv;

	ck_assert_int_eq(0, pipe(fds));

	memset(&ctx, 0, sizeof(ctx));
	ctx.fd = fds[RDFD];

	send_input(fds[WRFD], "potato ");
	send_input(fds[WRFD], "123456 ");
	send_input(fds[WRFD], "[ achoo ] ");
	send_input(fds[WRFD], "[ achoo1, achoo2, achoo3 ] ");
	send_input(fds[WRFD], "{ a=b, c=d, 1=2 } ");
	send_input(fds[WRFD], "{ a = [ [ b ], [ c ] ], d = [ [ e, f ] ] } ");
	send_input(fds[WRFD], "[{a={b=c,d=e},f={g=h}},{j=k}]");
	close(fds[WRFD]);

	/* potato */
	value = accept_value(&ctx, NULL);
	ck_value_str("potato", value);

	/* 123456 */
	value = accept_value(&ctx, NULL);
	ck_value_str("123456", value);

	/* [ achoo ] */
	value = accept_value(&ctx, NULL);
	ck_assert_int_eq(VALT_SET, value.type);

		node = STAILQ_FIRST(&value.v.set);
		ck_value_str("achoo", node->value);

		node = STAILQ_NEXT(node, hook);
		ck_assert_ptr_eq(NULL, node);

	/* [ achoo1, achoo2, achoo3 ] */
	value = accept_value(&ctx, NULL);
	ck_assert_int_eq(VALT_SET, value.type);

		node = STAILQ_FIRST(&value.v.set);
		ck_value_str("achoo1", node->value);

		node = STAILQ_NEXT(node, hook);
		ck_value_str("achoo2", node->value);

		node = STAILQ_NEXT(node, hook);
		ck_value_str("achoo3", node->value);

		node = STAILQ_NEXT(node, hook);
		ck_assert_ptr_eq(NULL, node);

	/* { a=b, c=d, 1=2 } */
	value = accept_value(&ctx, NULL);
	ck_assert_int_eq(VALT_MAP, value.type);

		kv = STAILQ_FIRST(&value.v.map);
		ck_keyval_str("a", "b", kv);

		kv = STAILQ_NEXT(kv, hook);
		ck_keyval_str("c", "d", kv);

		kv = STAILQ_NEXT(kv, hook);
		ck_keyval_str("1", "2", kv);

		kv = STAILQ_NEXT(kv, hook);
		ck_assert_ptr_eq(NULL, kv);

	/* { a = [ [ b ], [ c ] ], d = [ [ e, f ] ] } */
	value = accept_value(&ctx, NULL);
	ck_assert_int_eq(VALT_MAP, value.type);

		/* a = [ [ b ], [ c ] ] */
		kv = STAILQ_FIRST(&value.v.map);
		ck_assert_str_eq("a", kv->key);
		ck_assert_int_eq(VALT_SET, kv->value.type);

			/* [ b ] */
			node = STAILQ_FIRST(&kv->value.v.set);
			ck_assert_int_eq(VALT_SET, node->value.type);

				/* b */
				subnode = STAILQ_FIRST(&node->value.v.set);
				ck_value_str("b", subnode->value);

				/* Last */
				subnode = STAILQ_NEXT(subnode, hook);
				ck_assert_ptr_eq(NULL, subnode);

			/* [ c ] */
			node = STAILQ_NEXT(node, hook);
			ck_assert_int_eq(VALT_SET, node->value.type);

				/* c */
				subnode = STAILQ_FIRST(&node->value.v.set);
				ck_value_str("c", subnode->value);

				/* Last */
				subnode = STAILQ_NEXT(subnode, hook);
				ck_assert_ptr_eq(NULL, subnode);

			/* Last */
			node = STAILQ_NEXT(node, hook);
			ck_assert_ptr_eq(NULL, node);

		/* d = [ [ e, f ] ] */
		kv = STAILQ_NEXT(kv, hook);
		ck_assert_str_eq("d", kv->key);
		ck_assert_int_eq(VALT_SET, kv->value.type);

			/* [ e, f ] */
			node = STAILQ_FIRST(&kv->value.v.set);
			ck_assert_int_eq(VALT_SET, node->value.type);

				/* e */
				subnode = STAILQ_FIRST(&node->value.v.set);
				ck_value_str("e", subnode->value);

				/* f */
				subnode = STAILQ_NEXT(subnode, hook);
				ck_value_str("f", subnode->value);

				/* Last */
				subnode = STAILQ_NEXT(subnode, hook);
				ck_assert_ptr_eq(NULL, subnode);

			/* Last */
			node = STAILQ_NEXT(node, hook);
			ck_assert_ptr_eq(NULL, node);

		/* Last */
		kv = STAILQ_NEXT(kv, hook);
		ck_assert_ptr_eq(NULL, kv);

	/* [ { a = { b=c, d=e }, f = { g=h } }, { j=k } ] */
	value = accept_value(&ctx, NULL);
	ck_assert_int_eq(VALT_SET, value.type);

		/* { a = { b=c, d=e }, f = { g=h } } */
		node = STAILQ_FIRST(&value.v.set);
		ck_assert_int_eq(VALT_MAP, node->value.type);

			/* a = { b=c, d=e } */
			kv = STAILQ_FIRST(&node->value.v.map);
			ck_assert_str_eq("a", kv->key);

				/* b=c */
				subkv = STAILQ_FIRST(&kv->value.v.map);
				ck_keyval_str("b", "c", subkv);

				/* d=e */
				subkv = STAILQ_NEXT(subkv, hook);
				ck_keyval_str("d", "e", subkv);

				/* Last */
				subkv = STAILQ_NEXT(subkv, hook);
				ck_assert_ptr_eq(NULL, subkv);

			/* f = { g=h } */
			kv = STAILQ_NEXT(kv, hook);
			ck_assert_str_eq("f", kv->key);
			ck_assert_int_eq(VALT_MAP, kv->value.type);

				/* g=h */
				subkv = STAILQ_FIRST(&kv->value.v.map);
				ck_keyval_str("g", "h", subkv);

				/* Last */
				subkv = STAILQ_NEXT(subkv, hook);
				ck_assert_ptr_eq(NULL, subkv);

			/* Last */
			kv = STAILQ_NEXT(kv, hook);
			ck_assert_ptr_eq(NULL, kv);

		/* { j=k } */
		node = STAILQ_NEXT(node, hook);
		ck_assert_int_eq(VALT_MAP, node->value.type);

			kv = STAILQ_FIRST(&node->value.v.map);
			ck_keyval_str("j", "k", kv);

			kv = STAILQ_NEXT(kv, hook);
			ck_assert_ptr_eq(NULL, kv);

		/* Last */
		node = STAILQ_NEXT(node, hook);
		ck_assert_ptr_eq(NULL, node);
}
END_TEST

static void
init_ctx(struct rd_parse_context *ctx, struct rpki_tree *tree,
    char const *name, char const *content)
{
	int fds[2];
	size_t content_len;

	ck_assert_int_eq(0, pipe(fds));

	content_len = strlen(content);
	ck_assert_uint_eq(content_len, write(fds[1], content, content_len));
	close(fds[1]);

	memset(ctx, 0, sizeof(*ctx));
	memset(tree, 0, sizeof(*tree));
	ctx->fd = fds[0];
	ctx->path = name;
	ctx->line = 1;
	ctx->result = tree;
}

static void
ck_gnode(struct rd_parse_context *ctx, char const *name)
{
	size_t namelen;
	struct rpki_tree_node *node;

	namelen = strlen(name);
	HASH_FIND(ghook, ctx->result->nodes, name, namelen, node);
	ck_assert_ptr_ne(NULL, node);
	ck_assert_str_eq(name, node->meta.name);
}

static void
ck_child(struct rpki_tree_node *parent, char const *name)
{
	size_t namelen;
	struct rpki_tree_node *child;

	ck_assert_ptr_ne(NULL, parent);

	namelen = strlen(name);
	HASH_FIND(phook, parent->children, name, namelen, child);
	ck_assert_ptr_ne(NULL, child);
	ck_assert_str_eq(name, child->meta.name);
}

static void
ck_global(struct rd_parse_context *ctx, ...)
{
	va_list ap;
	char const *name;
	unsigned int n = 0;

	va_start(ap, ctx);
	while (va_arg(ap, char const *) != NULL)
		n++;
	va_end(ap);

	ck_assert_uint_eq(n, HASH_CNT(ghook, ctx->result->nodes));
	va_start(ap, ctx);
	while ((name = va_arg(ap, char const *)) != NULL)
		ck_gnode(ctx, name);
	va_end(ap);
}

static void
ck_root(struct rd_parse_context *ctx, char const *name)
{
	ck_assert_ptr_ne(NULL, ctx->result->root);
	ck_assert_str_eq(name, ctx->result->root->meta.name);
}

static void
ck_children(struct rpki_tree_node *parent, ...)
{
	va_list ap;
	char const *child_name;
	unsigned int n = 0;

	va_start(ap, parent);
	while (va_arg(ap, char const *) != NULL)
		n++;
	va_end(ap);

	if (n == 0) {
		ck_assert_ptr_eq(NULL, parent->children);
		return;
	}

	ck_assert_uint_eq(n, HASH_CNT(phook, parent->children));
	va_start(ap, parent);
	while ((child_name = va_arg(ap, char const *)) != NULL)
		ck_child(parent, child_name);
	va_end(ap);
}

static struct rpki_tree_node *
find_descendant(struct rd_parse_context *ctx, ...)
{
	struct rpki_tree_node *node, *tmp;
	va_list ap;
	char const *name;

	node = ctx->result->root;

	va_start(ap, ctx);
	while ((name = va_arg(ap, char const *)) != NULL) {
		HASH_FIND(phook, node->children, name, strlen(name), tmp);
		ck_assert_ptr_ne(NULL, tmp);
		node = tmp;
	}
	va_end(ap);

	return node;
}

START_TEST(check_read_tree)
{
	struct rd_parse_context ctx;
	struct rpki_tree tree;
	struct rpki_tree_node *node;

	/******************/

	init_ctx(&ctx, &tree, "Just the TA", "test.ta");
	read_tree(&ctx);

	ck_global(&ctx, "test.ta", NULL);
	ck_root(&ctx, "test.ta");

	/******************/

	init_ctx(&ctx, &tree, "Minimal tree",
		"test.ta\n"
		"	child.cer");
	read_tree(&ctx);

	ck_global(&ctx, "test.ta", "child.cer", NULL);
	ck_root(&ctx, "test.ta");
	ck_children(ctx.result->root, "child.cer", NULL);

	/******************/

	init_ctx(&ctx, &tree, "Same, but newline at the end",
		"test.ta\n"
		"	child.cer\n");
	read_tree(&ctx);

	ck_global(&ctx, "test.ta", "child.cer", NULL);
	ck_root(&ctx, "test.ta");
	ck_children(ctx.result->root, "child.cer", NULL);

	/******************/

	init_ctx(&ctx, &tree, "Comments and empty lines",
		"# Lorem ipsum dolor sit amet.\n"
		"root.achoo # Donec sollicitudin ipsum eget sodales\n"
		"\n"
		"	# Fusce pretium ultricies egestas. Sed.\n"
		"	ca1.cer\n"
		"\n"
		"	\"roa.roa\"\n"
		"		\n"
		"		# Etiam egestas condimentum sollicitudin. \n"
		"	# Donec lacinia et lectus eu mollis.   \n"
		"	\n"
		"	mft.mft # Cras dignissim at velit vitae");
	read_tree(&ctx);

	ck_global(&ctx, "root.achoo", "ca1.cer", "roa.roa", "mft.mft", NULL);
	ck_root(&ctx, "root.achoo");
	ck_children(ctx.result->root, "ca1.cer", "roa.roa", "mft.mft", NULL);

	/******************/

	init_ctx(&ctx, &tree, "More floors and indentation shenanigans",
		"root\n"
		"  1\n"
		"	11\n"
		"	       111\n"
		"	       112\n"
		"	12\n"
		"	\n"
		"\n"
		"	   121\n"
		"	   122\n"
		"  2\n"
		"  3\n");
	read_tree(&ctx);

	ck_global(&ctx, "root", "1", "11", "111", "112", "12", "121", "112",
	    "2", "3", NULL);
	ck_root(&ctx, "root");
	ck_children(ctx.result->root, "1", "2", "3", NULL);

	node = find_descendant(&ctx, "1", NULL);
	ck_children(node, "11", "12", NULL);
	node = find_descendant(&ctx, "1", "11", NULL);
	ck_children(node, "111", "112", NULL);
	node = find_descendant(&ctx, "1", "11", "111", NULL);
	ck_children(node, NULL);
	node = find_descendant(&ctx, "1", "11", "112", NULL);
	ck_children(node, NULL);
	node = find_descendant(&ctx, "1", "12", NULL);
	ck_children(node, "121", "122", NULL);
	node = find_descendant(&ctx, "1", "12", "121", NULL);
	ck_children(node, NULL);
	node = find_descendant(&ctx, "1", "12", "122", NULL);
	ck_children(node, NULL);
	node = find_descendant(&ctx, "2", NULL);
	ck_children(node, NULL);
	node = find_descendant(&ctx, "3", NULL);
	ck_children(node, NULL);
}
END_TEST

START_TEST(check_read_keyvals)
{
	struct rd_parse_context ctx;
	struct rpki_tree tree;
	struct rpki_tree_node *node;
	struct keyval *kv;
	struct kv_node *setnode;
	struct keyval *mapnode;

	/******************/

	init_ctx(&ctx, &tree, "Single integer tweak",
		"ta.cer\n"
		"[node: ta.cer]\n"
		"potato = 1\n");
	read_tree(&ctx);
	read_keyvals(&ctx);

	node = ctx.result->root;
	ck_assert_ptr_ne(NULL, node);
	kv = STAILQ_FIRST(&node->props);
	ck_keyval_str("potato", "1", kv);
	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);

	/******************/

	init_ctx(&ctx, &tree, "Multiple files",
		"ta.cer\n"
		"	ca.cer\n"
		"\n"
		"[node: ta.cer]\n"
		"potato = 12345\n"
		"\n"
		"[node: ca.cer]\n"
		"tomato = aoeui\n");
	read_tree(&ctx);
	read_keyvals(&ctx);

	node = ctx.result->root;
	ck_assert_ptr_ne(NULL, node);
	kv = STAILQ_FIRST(&node->props);
	ck_keyval_str("potato", "12345", kv);
	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);

	node = find_descendant(&ctx, "ca.cer", NULL);
	kv = STAILQ_FIRST(&node->props);
	ck_keyval_str("tomato", "aoeui", kv);
	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);

	/******************/

	init_ctx(&ctx, &tree, "Multiple props",
		"ta.cer\n"
		"[node: ta.cer]\n"
		"potato = 12345\n"
		"tomato = aoeui");
	read_tree(&ctx);
	read_keyvals(&ctx);

	node = ctx.result->root;
	ck_assert_ptr_ne(NULL, node);
	kv = STAILQ_FIRST(&node->props);
	ck_keyval_str("potato", "12345", kv);
	kv = STAILQ_NEXT(kv, hook);
	ck_keyval_str("tomato", "aoeui", kv);
	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);

	/******************/

	init_ctx(&ctx, &tree, "Other data types",
		"ta.cer\n"
		"[node: ta.cer]\n"
		"a.b.c = [ 12345, \"23456\" ]\n"
		"\"a.b.d\" = { \"aoeui\" = \"333\", dhtns = 444 }");
	read_tree(&ctx);
	read_keyvals(&ctx);

	node = ctx.result->root;
	ck_assert_ptr_ne(NULL, node);

	kv = STAILQ_FIRST(&node->props);
	ck_assert_str_eq("a.b.c", kv->key);
	ck_assert_int_eq(VALT_SET, kv->value.type);

		setnode = STAILQ_FIRST(&kv->value.v.set);
		ck_assert_uint_eq(VALT_STR, setnode->value.type);
		ck_assert_str_eq("12345", setnode->value.v.str);

		setnode = STAILQ_NEXT(setnode, hook);
		ck_assert_uint_eq(VALT_STR, setnode->value.type);
		ck_assert_str_eq("23456", setnode->value.v.str);

		setnode = STAILQ_NEXT(setnode, hook);
		ck_assert_ptr_eq(NULL, setnode);

	kv = STAILQ_NEXT(kv, hook);
	ck_assert_str_eq("a.b.d", kv->key);
	ck_assert_int_eq(VALT_MAP, kv->value.type);

		mapnode = STAILQ_FIRST(&kv->value.v.map);
		ck_assert_str_eq("aoeui", mapnode->key);
		ck_assert_uint_eq(VALT_STR, mapnode->value.type);
		ck_assert_str_eq("333", mapnode->value.v.str);

		mapnode = STAILQ_NEXT(mapnode, hook);
		ck_assert_str_eq("dhtns", mapnode->key);
		ck_assert_uint_eq(VALT_STR, mapnode->value.type);
		ck_assert_str_eq("444", mapnode->value.v.str);

		mapnode = STAILQ_NEXT(mapnode, hook);
		ck_assert_ptr_eq(NULL, mapnode);

	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);

	/******************/

	init_ctx(&ctx, &tree, "Whitespace, comments",
		"ta.cer\n"
		"		# Integer eget dui sit amet.\n"
		"[node: ta.cer] # Donec a urna turpis\n"
		"  # Nulla ut tellus nec augue malesuada aliquet in vel eros\n"
		"a\n" "=\n" "\"aa bb cc\n" "dd ee ff\"\n"
		"b\n" "=\n" "[\n" "12345\n" ",\n" "23456\n" "] "
		"c\n" "=\n" "{\n" "aoeui\n" "=\n" "333\n" ",\n" "dhtns\n" "=\n" "444\n" "}\n");
	read_tree(&ctx);
	read_keyvals(&ctx);

	node = ctx.result->root;
	ck_assert_ptr_ne(NULL, node);

	kv = STAILQ_FIRST(&node->props);
	ck_keyval_str("a", "aa bb cc\ndd ee ff", kv);

	kv = STAILQ_NEXT(kv, hook);
	ck_assert_str_eq("b", kv->key);
	ck_assert_int_eq(VALT_SET, kv->value.type);

		setnode = STAILQ_FIRST(&kv->value.v.set);
		ck_assert_uint_eq(VALT_STR, setnode->value.type);
		ck_assert_str_eq("12345", setnode->value.v.str);

		setnode = STAILQ_NEXT(setnode, hook);
		ck_assert_uint_eq(VALT_STR, setnode->value.type);
		ck_assert_str_eq("23456", setnode->value.v.str);

		setnode = STAILQ_NEXT(setnode, hook);
		ck_assert_ptr_eq(NULL, setnode);

	kv = STAILQ_NEXT(kv, hook);
	ck_assert_str_eq("c", kv->key);
	ck_assert_int_eq(VALT_MAP, kv->value.type);

		mapnode = STAILQ_FIRST(&kv->value.v.map);
		ck_assert_str_eq("aoeui", mapnode->key);
		ck_assert_uint_eq(VALT_STR, mapnode->value.type);
		ck_assert_str_eq("333", mapnode->value.v.str);

		mapnode = STAILQ_NEXT(mapnode, hook);
		ck_assert_str_eq("dhtns", mapnode->key);
		ck_assert_uint_eq(VALT_STR, mapnode->value.type);
		ck_assert_str_eq("444", mapnode->value.v.str);

		mapnode = STAILQ_NEXT(mapnode, hook);
		ck_assert_ptr_eq(NULL, mapnode);

	kv = STAILQ_NEXT(kv, hook);
	ck_assert_ptr_eq(NULL, kv);
}
END_TEST

static Suite *
address_load_suite(void)
{
	Suite *suite;
	TCase *parser;

	parser = tcase_create("Parser");
	tcase_add_test(parser, check_accept_value);
	tcase_add_test(parser, check_read_tree);
	tcase_add_test(parser, check_read_keyvals);

	suite = suite_create("fields");
	suite_add_tcase(suite, parser);
	return suite;
}

int
main(void)
{
	SRunner *runner;
	int tests_failed;

	runner = srunner_create(address_load_suite());
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
