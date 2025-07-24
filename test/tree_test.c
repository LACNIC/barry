#include "../src/rpki_tree.c"

#include <check.h>

#define RDFD 0
#define WRFD 1

unsigned int verbosity = 2;

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

static Suite *
address_load_suite(void)
{
	Suite *suite;
	TCase *parser;

	parser = tcase_create("Parser");
	tcase_add_test(parser, check_accept_value);

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
