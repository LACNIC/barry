#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "alloc.h"
#include "print.h"
#include "str.h"

enum output_format {
	OF_PDU,
	OF_RAPPORT,
};

static char *action;
static char *server;
static char *port = "323";
static enum output_format format;
static uint8_t version = 2;
static atomic_uint session;
static uint32_t serial;
static char const *input;

static FILE *infile; /* (Interactive) input file */

unsigned int verbosity;
bool print_colors;

static char const *cmd = "";
static char const *flg = "";
static char const *var = "";
static char const *enm = "";
static char const *man = "";
static char const *ref = "";
static char const *rst = "";

static int rtrfd; /* RTR socket file descriptor */
static pthread_t socket_thread;

struct line_reader {
	char *line;
	size_t lsize;
	char *saveptr;
	bool first;
	unsigned int lvl;
};

#define PDUBUFLEN 1024

struct pdu {
	int fd;
	unsigned char buf[PDUBUFLEN];
	size_t len;
	size_t offset; /* read offset */
};

typedef struct pdu *(*create_pdu_cb)(struct line_reader *);
typedef int (*print_pdu_cb)(struct pdu *, unsigned char *);

static create_pdu_cb get_create_pdu_cb(char const *);
static print_pdu_cb get_print_pdu_cb(unsigned char);

static int print_pdu_unknown(struct pdu *, unsigned char *);

static bool
streq(char const *str1, char const *str2)
{
	return strcmp(str1, str2) == 0;
}

/* CAN RETURN NULL. */
static char *
next_token(struct line_reader *rdr)
{
	char *tkn;
	tkn = strtok_r(rdr->first ? rdr->line : NULL, " \t\n\r\v\f", &rdr->saveptr);
	rdr->first = false;
	pr_trace("Received token: %s", tkn);
	return (rdr->lvl > 0 && streq(tkn, "]")) ? NULL : tkn;
}

static void
print_help(void)
{
	printf("Usage:\n");
	printf("  barry-rtr [%s-h%s] [%s-v%s[%sv%s]] [%s-c%s] [%s-f%s<format>%s] [%s-i%s<input-source>%s]\n", flg, rst, flg, rst, flg, rst, flg, rst, flg, var, rst, flg, var, rst);
	printf("      [%s-V%s<version>%s] [%s-s%s<session>%s] [%s-l%s<serial>%s]\n", flg, var, rst, flg, var, rst, flg, var, rst);
	printf("      %s<action>%s %s<server>%s [%s<port>%s]\n", var, rst, var, rst, var, rst);
	printf("\n");
	printf("%s<action>%s is either '%sreset%s', '%sserial%s' or '%sinteractive%s'.\n", var, rst, enm, rst, enm, rst, enm, rst);
	printf("  - '%sreset%s' connects, sends one Reset Query PDU, prints all received PDUs,\n", enm, rst);
	printf("    and exits once a %sterminating PDU%s is received.\n", ref, rst);
	printf("  - '%sserial%s' connects, sends one Serial Query PDU, prints all received PDUs,\n", enm, rst);
	printf("    and exits once a %sterminating PDU%s is received.\n", ref, rst);
	printf("  - '%sinteractive%s' connects, then expects commands from %s-i%s.\n", enm, rst, flg, rst);
	printf("    Input 'help' during interactive mode for more information.\n");
	printf("\n");
	printf("The %sterminating PDU%ss are End Of Data, Cache Reset, Error Report and unknown.\n", ref, rst);
	printf("\n");
	printf("%s<server>%s and %s<port>%s are the RTR server name and service, respectively.\n", var, rst, var, rst);
	printf("  They are resolved via %sgetaddrinfo(3)%s.\n", man, rst);
	printf("  %s<port>%s defaults to %s.\n", var, rst, port);
	printf("\n");
	printf("Options:\n");
	printf("  %s-h%s prints this wall of text\n", flg, rst);
	printf("  %s-v%s increases verbosity\n", flg, rst);
	printf("  %s-c%s colorizes output\n", flg, rst);
	printf("  %s-f%s sets output format:\n", flg, rst);
	printf("    * '%spdu%s': Print exhaustive PDU stream (default)\n", enm, rst);
	printf("    * '%srapport%s': Print resources only\n", enm, rst);
	printf("  %s-V%s sets RTR version number (Default: Latest supported)\n", flg, rst);
	printf("  %s-s%s sets the session ID (Default: %u)\n", flg, rst, atomic_load(&session));
	printf("     (Effective in '%sserial%s' and '%sinteractive%s' modes only)\n", enm, rst, enm, rst);
	printf("  %s-l%s sets the request's serial\n", flg, rst);
	printf("     (Effective in '%sserial%s' mode only)\n", enm, rst);
	printf("  %s-i%s sets the input Unix socket name, or '-' (default) for standard input.\n", flg, rst);
	printf("     (Effective in '%sinteractive%s' mode only)\n", enm, rst);
	printf("\n");
	printf("Sample send command to Unix socket:\n");
	printf("    $ echo \"reset-query\" | barry-ncu %s<input-source>%s\n", var, rst);
}

static void
print_command_help(void)
{
	printf("Values surrounded by %s<angular quotation marks>%s are defaults.\n", var, rst);
	printf("\n");

	printf("Metacommands:\n");
	printf("\n");

	printf("%sversion%s %s<%s-V%s>%s\n", cmd, rst, var, flg, var, rst);
	printf("   Sets the default RTR version number sent by all subsequent PDUs.\n");
	printf("%shelp%s\n", cmd, rst);
	printf("   Prints this wall of text.\n");
	printf("%sraw%s hex       (Eg. \"%sraw%s 001122\")\n", cmd, rst, cmd, rst);
	printf("   Send raw hexadecimal bytes.\n");
	printf("%ssleep%s %s<1000>%s\n", cmd, rst, var, rst);
	printf("   Wait the given amount of milliseconds.\n");
	printf("%sexit%s\n", cmd, rst);
	printf("   Quits.\n");
	printf("\n");

	printf("PDU dispatching:\n");
	printf("\n");

	printf("%sreset-query%s    [version %s<%s-V%s>%s] [type %s<2>%s] [zero       %s<0>%s] [length  %s<8>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("%sserial-query%s   [version %s<%s-V%s>%s] [type %s<1>%s] [session %s<auto>%s] [length %s<12>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [serial %s<1>%s]\n", var, rst);
	printf("%sserial-notify%s  [version %s<%s-V%s>%s] [type %s<0>%s] [session %s<auto>%s] [length %s<12>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [serial %s<1>%s]\n", var, rst);
	printf("%scache-response%s [version %s<%s-V%s>%s] [type %s<3>%s] [session %s<auto>%s] [length  %s<8>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("%sipv4-prefix%s    [version %s<%s-V%s>%s] [type %s<4>%s] [zero1      %s<0>%s] [length %s<20>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [flags %s<1>%s] [plen %s<0>%s] [maxlen %s<0>%s] [zero2 %s<0>%s]\n",
	    var, rst, var, rst, var, rst, var, rst);
	printf("               [prefix %s<0.0.0.0>%s] [as %s<0>%s]\n", var, rst, var, rst);
	printf("%sipv6-prefix%s    [version %s<%s-V%s>%s] [type %s<6>%s] [zero1      %s<0>%s] [length %s<32>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [flags %s<1>%s] [plen %s<0>%s] [maxlen %s<0>%s] [zero2 %s<0>%s]\n",
	    var, rst, var, rst, var, rst, var, rst);
	printf("               [prefix %s<::>%s] [as %s<0>%s]\n", var, rst, var, rst);
	printf("%send-of-data%s    [version %s<%s-V%s>%s] [type %s<7>%s] [session %s<auto>%s] [length %s<auto>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [serial %s<1>%s] [refresh %s<3600>%s] [retry %s<600>%s] [expire %s<7200>%s]\n",
	    var, rst, var, rst, var, rst, var, rst);
	printf("%scache-reset%s    [version %s<%s-V%s>%s] [type %s<8>%s] [zero %s<0>%s] [length %s<8>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("%srouter-key%s     [version %s<%s-V%s>%s] [type %s<9>%s] [flags %s<1>%s] [zero %s<0>%s] [length %s<auto>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst, var, rst);
	printf("               [ski %s<0x00/160>%s] [as %s<0>%s] [spki %s<>%s]\n", var, rst, var, rst, var, rst);
	printf("%serror-report%s   [version %s<%s-V%s>%s] [type %s<10>%s] [error-code %s<1>%s] [length %s<auto>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst);
	printf("               [encapsulated-pdu-length %s<auto>%s] [encapsulated-pdu %s<>%s]\n", var, rst, var, rst);
	printf("               [error-text-length %s<auto>%s] [error-text %s<>%s]\n", var, rst, var, rst);
	printf("%saspa-pdu%s       [version %s<%s-V%s>%s] [type %s<11>%s] [flags %s<1>%s] [zero %s<0>%s] [length %s<auto>%s]\n",
	    cmd, rst, var, flg, var, rst, var, rst, var, rst, var, rst, var, rst);
	printf("               [customer %s<0>%s] [providers %s<[ ]>%s]\n", var, rst, var, rst);
	printf("\n");

	printf("The default value of %s-V%s is the latest supported RTR version.\n", flg, rst);
	printf("At the moment, this is 2.\n");
	printf("\n");

	printf("The default value of 'session' is overridden by the actual session number\n");
	printf("whenever the server announces it.\n");
	printf("\n");

	printf("If 'serial', 'refresh', 'retry' and/or 'expire' are defined in %send-of-data%s,\n", enm, rst);
	printf("they are all included. Otherwise they are all excluded.\n");
	printf("The default value of 'length' automatically adapts.\n");
	printf("\n");

	printf("The default value of %srouter-key%s 'length' is 32 + 'ski' length.\n", enm, rst);
	printf("\n");

	printf("'encapsulated-pdu' is another PDU, surrounded by square brackets. Example:\n");
	printf("    %serror-report%s encapsulated-pdu [ %sserial-query%s serial 2 ]\n", enm, rst, enm, rst);
	printf("\n");

	printf("'providers' is a sequence of u32s separated by whitespace, surrounded by square\n");
	printf("brackets.\n");
	printf("\n");
}

static int
parse_u8(char const *what, char *str, uint8_t *value)
{
	unsigned long v;

	if (str2ul(what, str, UINT8_MAX, &v) != 0)
		return EINVAL;

	*value = v;
	return 0;
}

static int
next_u8(struct line_reader *rdr, char const *what, uint8_t *value)
{
	return parse_u8(what, next_token(rdr), value);
}

static int
parse_u16(char const *what, char const *str, uint16_t *result)
{
	unsigned long v;

	if (str2ul(what, str, UINT16_MAX, &v) != 0)
		return EINVAL;

	*result = v;
	return 0;
}

static int
next_u16(struct line_reader *rdr, char const *what, uint16_t *value)
{
	return parse_u16(what, next_token(rdr), value);
}

static int
parse_u32(char const *what, char const *str, uint32_t *result)
{
	unsigned long v;

	if (str2ul(what, str, UINT32_MAX, &v) != 0)
		return EINVAL;

	*result = v;
	return 0;
}

static int
next_u32(struct line_reader *rdr, char const *what, uint32_t *value)
{
	return parse_u32(what, next_token(rdr), value);
}

static int
next_u32_array(struct line_reader *rdr, char const *what,
    uint32_t **_array, size_t *_len)
{
	char *tkn;
	uint32_t *array;
	size_t capacity;
	size_t len;
	int error;

	if (*_array) {
		free(*_array);
		*_array = NULL;
		*_len = 0;
	}

	tkn = next_token(rdr);
	if (!tkn || !streq(tkn, "[")) {
		pr_err("Expected '[' after '%s'.", what);
		return EINVAL;
	}

	capacity = 16;
	len = 0;
	array = pmalloc(capacity);

	while ((tkn = next_token(rdr)) != NULL) {
		if (streq(tkn, "]"))
			break;

		if (len >= capacity) {
			capacity *= 2;
			array = prealloc(array, capacity);
		}

		error = parse_u32(what, tkn, &array[len]);
		if (error)
			goto fail;

		len++;
	}

	*_array = array;
	*_len = len;
	return 0;

fail:	free(array);
	return error;
}

static int
next_string(struct line_reader *rdr, char const *what, char const **value)
{
	*value = next_token(rdr); /* TODO Fast-assed */
	return 0;
}

static int
next_addr(struct line_reader *rdr, char const *what, int af, void *value)
{
	char *token;
	int res;

	token = next_token(rdr);
	if (!token) {
		pr_err("Expected an IP address after '%s'.", what);
		return EINVAL;
	}

	res = inet_pton(af, token, value);
	switch (res) {
	case 1:
		return 0;
	case 0:
		pr_err("Cannot parse as an IPv%u address: %s",
		    (af == AF_INET) ? 4 : 6, token);
		return EINVAL;
	case -1:
		pr_err("Address family unknown: %s", strerror(errno));
		return EINVAL;
	}

	pr_err("Unknown inet_pton() result: %d", res);
	return EINVAL;
}

static unsigned int
chr2hex(char chr)
{
	if ('0' <= chr && chr <= '9')
		return chr - '0';
	if ('a' <= chr && chr <= 'f')
		return chr - 'a' + 10;
	if ('A' <= chr && chr <= 'F')
		return chr - 'A' + 10;
	return 32;
}

static int
token2bytes(char const *token, char const *what,
    unsigned char **res, size_t *reslen)
{
	size_t token_len;
	unsigned char *buf;
	size_t buflen;
	size_t i;

	token_len = strlen(token);
	if (token_len & 1) {
		pr_err("Byte array '%s' needs an even number of digits.", what);
		return EINVAL;
	}

	buflen = token_len / 2;
	buf = pmalloc(buflen);
	for (i = 0; i < buflen; i++)
		buf[i] = (chr2hex(token[2*i]) << 4) + chr2hex(token[2*i + 1]);

	*res = buf;
	*reslen = buflen;
	return 0;
}

static int
next_bytes(struct line_reader *rdr, char const *what,
    unsigned char **res, size_t *reslen)
{
	char *token;

	token = next_token(rdr);
	if (!token) {
		pr_err("Expected a hexadecimal string after '%s'.", what);
		return EINVAL;
	}

	return token2bytes(token, what, res, reslen);
}

static void
enable_colors(void)
{
	print_colors = true;
	cmd = C_GRN;
	flg = C_CYAN;
	var = C_YLLW;
	enm = C_GRN;
	man = C_BOLD;
	ref = C_UNDERLINE;
	rst = C_RST;
}

static void
parse_getopt_format(void)
{
	if (strcmp(optarg, "pdu") == 0)
		format = OF_PDU;
	else if (strcmp(optarg, "rapport") == 0)
		format = OF_RAPPORT;
	else {
		pr_err("-f (--format) must be 'pdu' (default) or 'rapport).");
		exit(EXIT_FAILURE);
	}
}

static char const *
format2str(enum output_format f)
{
	switch (f) {
	case OF_PDU:		return "pdu";
	case OF_RAPPORT:	return "rapport";
	default:		return NULL;
	}
}

static void
parse_getopt_version(void)
{
	if (parse_u8("version", optarg, &version) != 0)
		exit(EXIT_FAILURE);
}

static void
parse_getopt_session(void)
{
	uint16_t s;
	if (parse_u16("session", optarg, &s) != 0)
		exit(EXIT_FAILURE);
	atomic_store(&session, s);
}

static void
parse_getopt_serial(void)
{
	if (parse_u32("serial", optarg, &serial) != 0)
		exit(EXIT_FAILURE);
}

static void
parse_options(int argc, char **argv)
{
	static struct option opts[] = {
		{ "help",    no_argument,       0, 'h' },
		{ "verbose", no_argument,       0, 'v' },
		{ "color",   no_argument,       0, 'c' },
		{ "format",  required_argument, 0, 'f' },
		{ "version", required_argument, 0, 'V' },
		{ "session", required_argument, 0, 's' },
		{ "serial",  required_argument, 0, 'l' },
		{ "input",   required_argument, 0, 'i' },
		{ 0 }
	};
	int opt;
	bool help = false;

	atomic_init(&session, 0);

	while ((opt = getopt_long(argc, argv, "hvcf:V:s:l:i:", opts, NULL)) != -1)
		switch (opt) {
		case 'h':	help = true;		break;
		case 'v':	verbosity++;		break;
		case 'c':	enable_colors();	break;
		case 'f':	parse_getopt_format();	break;
		case 'V':	parse_getopt_version();	break;
		case 's':	parse_getopt_session();	break;
		case 'l':	parse_getopt_serial();	break;
		case 'i':	input = optarg;		break;
		case '?':	print_help();		exit(EXIT_FAILURE);
		}

	/* Do this outside of the switch to catch -c even if it's after -h */
	if (help) {
		print_help();
		exit(EXIT_SUCCESS);
	}

	switch (argc - optind) {
	case 3:
		port = argv[optind + 2];
		/* No break */
	case 2:
		server = argv[optind + 1];
		action = argv[optind];
		break;
	default:
		pr_err("Wrong number of unflagged arguments: %d", argc - optind);
		print_help();
		exit(EXIT_FAILURE);
	}

	pr_debug("Configuration:");
	pr_debug("   action         = %s", action);
	pr_debug("   server         = %s", server);
	pr_debug("   port           = %s", port);
	pr_debug("   --verbose (-v) = %u", verbosity);
	pr_debug("   --color   (-c) = %u", print_colors);
	pr_debug("   --format  (-f) = %s", format2str(format));
	pr_debug("   --version (-V) = %u", version);
	pr_debug("   --session (-s) = %u", session);
	pr_debug("   --serial  (-l) = %u", serial);
	pr_debug("   --input   (-i) = %s", input);
	pr_debug("");
}

static void
sigterm_handler(int signum)
{
	unlink(input);

	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

static void
open_infile(void)
{
	struct sigaction action;
	struct sockaddr_un srv;
	int clientfd;

	if (!input || strcmp(input, "-") == 0) {
		input = NULL;
		return;
	}

	pr_trace("Setting up input socket.");

	unlink(input);

	if (strlen(input) > sizeof(srv.sun_path) - 1)
		panic("--input is too long. (max is %zu characters)",
		    sizeof(srv.sun_path) - 1);
	srv.sun_family = AF_UNIX;
	strcpy(srv.sun_path, input);

	memset(&action, 0, sizeof(action));
	action.sa_handler = sigterm_handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGTERM, &action, NULL) == -1)
		pr_err("SIGTERM handler registration failure: %s",
		    strerror(errno));

	clientfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (clientfd < 0)
		panic("Unable to create socket: %s", strerror(errno));
	if (bind(clientfd, (struct sockaddr *)&srv, sizeof(srv)) < 0)
		panic("Cannot bind socket: %s", strerror(errno));
	if ((infile = fdopen(clientfd, "r")) == NULL)
		panic("Cannot convert fd to in FILE: %s", strerror(errno));
}

static void
close_infile(void)
{
	if (input) {
		pr_trace("Closing input socket.");
		fclose(infile);
		unlink(input);
	}
}

static void
connect_socket(void)
{
	struct addrinfo hints = { 0 };
	struct addrinfo *alternatives, *alt;
	int error;

	pr_trace("Connecting to RTR server.");

	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	error = getaddrinfo(server, port, &hints, &alternatives);
	if (error)
		panic("getaddrinfo: %s", gai_strerror(error));

	for (alt = alternatives; alt != NULL; alt = alt->ai_next) {
		rtrfd = socket(alt->ai_family, alt->ai_socktype, alt->ai_protocol);
		if (rtrfd < 0) {
			pr_err("socket(%s, %s): %s", server, port,
			    strerror(errno));
			continue;
		}
		if (connect(rtrfd, alt->ai_addr, alt->ai_addrlen) != -1)
			break; /* Success */

		pr_err("connect(%s, %s): %s", server, port, strerror(errno));
		close(rtrfd);
	}

	freeaddrinfo(alternatives);

	if (!alt)
		panic("None of the addrinfo candidates could connect.");
}

static void
close_socket(void)
{
	pr_trace("Closing RTR socket.");
	close(rtrfd);
}

static size_t
add_u8(struct pdu *pdu, size_t offset, uint8_t u8)
{
	pdu->buf[offset] = u8;
	return 1;
}

static size_t
__add_u16(unsigned char *buf, uint16_t u16)
{
	buf[0] = (u16 >> 8) & 0xFFu;
	buf[1] = (u16 >> 0) & 0xFFu;
	return 2;
}

static size_t
add_u16(struct pdu *pdu, size_t offset, uint16_t u16)
{
	return __add_u16(&pdu->buf[offset], u16);
}

static size_t
__add_u32(unsigned char *buf, uint32_t u32)
{
	buf[0] = (u32 >> 24) & 0xFFu;
	buf[1] = (u32 >> 16) & 0xFFu;
	buf[2] = (u32 >>  8) & 0xFFu;
	buf[3] = (u32 >>  0) & 0xFFu;
	return 4;
}

static size_t
add_u32(struct pdu *pdu, size_t offset, uint32_t u32)
{
	return __add_u32(&pdu->buf[offset], u32);
}

static void
full_write(unsigned char *msg, size_t len)
{
	ssize_t written;

	for (; len > 0; len -= written) {
		written = write(rtrfd, msg, len);
		if (written < 0)
			panic("write(): %s", strerror(errno));
	}
}

static bool
is_type(char const *token)
{
	return (strcmp(token, "type") == 0) || (strcmp(token, "pdu-type") == 0);
}

static struct pdu *
create_pdu(size_t size, uint8_t v, uint8_t t, uint16_t f3, uint32_t l)
{
	struct pdu *res;

	if (size > PDUBUFLEN)
		panic("PDU length %zu > %u", size, PDUBUFLEN);

	res = pmalloc(sizeof(struct pdu));
	res->fd = -1;
	res->len = size;
	res->offset = 0;

	add_u8(res, 0, v);
	add_u8(res, 1, t);
	add_u16(res, 2, f3);
	add_u32(res, 4, l);

	return res;
}

static struct pdu *
create_8pdu(struct line_reader *rdr, uint8_t pdu_type,
    char const *key3, uint16_t val3)
{
	uint8_t _version = version;
	uint32_t length = 8;
	char *token;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (is_type(token))
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, key3) == 0)
			error = next_u16(rdr, key3, &val3);
		else if (strcmp(token, "length") == 0)
			error = next_u32(rdr, "length", &length);
		else {
			pr_err("Unknown token: %s", token);
			return NULL;
		}
		if (error)
			return NULL;
	}

	return create_pdu(8, _version, pdu_type, val3, length);
}

static struct pdu *
create_12pdu(struct line_reader *rdr, uint8_t pdu_type)
{
	uint8_t _version = version;
	uint16_t _session = atomic_load(&session);
	uint32_t length = 12;
	uint32_t serial = 1;
	char *token;
	struct pdu *pdu;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (is_type(token))
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, "session") == 0)
			error = next_u16(rdr, "session", &_session);
		else if (strcmp(token, "length") == 0)
			error = next_u32(rdr, "length", &length);
		else if (strcmp(token, "serial") == 0)
			error = next_u32(rdr, "serial", &serial);
		else {
			pr_err("Unknown token: %s", token);
			return NULL;
		}
		if (error)
			return NULL;
	}

	pdu = create_pdu(12, _version, pdu_type, _session, length);
	add_u32(pdu, 8, serial);
	return pdu;
}

static struct pdu *
create_ip_prefix_pdu(struct line_reader *rdr, int af)
{
	uint8_t _version = version;
	uint8_t pdu_type = (af == AF_INET) ? 4 : 6;
	uint16_t zero1 = 0;
	uint32_t length = (af == AF_INET) ? 20 : 32;
	uint8_t flags = 1;
	uint8_t plen = 0;
	uint8_t maxlen = 0;
	uint8_t zero2 = 0;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} pref = { 0 };
	uint32_t as = 0;
	char *token;
	struct pdu *pdu;
	size_t i;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (is_type(token))
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, "zero1") == 0)
			error = next_u16(rdr, "zero1", &zero1);
		else if (strcmp(token, "length") == 0)
			error = next_u32(rdr, "length", &length);
		else if (strcmp(token, "flags") == 0)
			error = next_u8(rdr, "flags", &flags);
		else if (strcmp(token, "plen") == 0)
			error = next_u8(rdr, "plen", &plen);
		else if (strcmp(token, "maxlen") == 0)
			error = next_u8(rdr, "maxlen", &maxlen);
		else if (strcmp(token, "zero2") == 0)
			error = next_u8(rdr, "zero2", &zero2);
		else if (strcmp(token, "prefix") == 0)
			error = next_addr(rdr, "prefix", af, &pref);
		else if (strcmp(token, "as") == 0)
			error = next_u32(rdr, "as", &as);
		else {
			pr_err("Unknown token: %s", token);
			return NULL;
		}
		if (error)
			return NULL;
	}

	switch (af) {
	case AF_INET:
		pdu = create_pdu(20, _version, pdu_type, zero1, length);
		add_u8(pdu, 8, flags);
		add_u8(pdu, 9, plen);
		add_u8(pdu, 10, maxlen);
		add_u8(pdu, 11, zero2);
		add_u32(pdu, 12, ntohl(pref.v4.s_addr));
		add_u32(pdu, 16, as);
		break;

	case AF_INET6:
		pdu = create_pdu(32, _version, pdu_type, zero1, length);
		add_u8(pdu, 8, flags);
		add_u8(pdu, 9, plen);
		add_u8(pdu, 10, maxlen);
		add_u8(pdu, 11, zero2);
		for (i = 0; i < 16; i++)
			add_u8(pdu, 12 + i, pref.v6.s6_addr[i]);
		add_u32(pdu, 28, as);
		break;

	default:
		pr_err("Unknown address family: %d", af);
		pdu = NULL;
	}

	return pdu;
}

static struct pdu *
create_serial_notify_pdu(struct line_reader *rdr)
{
	return create_12pdu(rdr, 0);
}

static struct pdu *
create_serial_query_pdu(struct line_reader *rdr)
{
	return create_12pdu(rdr, 1);
}

static struct pdu *
create_reset_query_pdu(struct line_reader *rdr)
{
	return create_8pdu(rdr, 2, "zero", 0);
}

static struct pdu *
create_cache_response_pdu(struct line_reader *rdr)
{
	return create_8pdu(rdr, 3, "session", atomic_load(&session));
}

static struct pdu *
create_ipv4_prefix_pdu(struct line_reader *rdr)
{
	return create_ip_prefix_pdu(rdr, AF_INET);
}

static struct pdu *
create_ipv6_prefix_pdu(struct line_reader *rdr)
{
	return create_ip_prefix_pdu(rdr, AF_INET6);
}

static struct pdu *
create_end_of_data_pdu(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t pdu_type = 7;
	uint16_t _session = atomic_load(&session);
	uint32_t length = 8;
	bool length_overridden = false;
	bool extended = false;
	uint32_t serial = 1;
	uint32_t refresh = 3600;
	uint32_t retry = 600;
	uint32_t expire = 7200;
	char *token;
	struct pdu *pdu;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (is_type(token))
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, "session") == 0)
			error = next_u16(rdr, "session", &_session);
		else if (strcmp(token, "length") == 0) {
			error = next_u32(rdr, "length", &length);
			length_overridden = true;
		} else if (strcmp(token, "serial") == 0) {
			error = next_u32(rdr, "serial", &serial);
			extended = true;
		} else if (strcmp(token, "refresh") == 0) {
			error = next_u32(rdr, "refresh", &refresh);
			extended = true;
		} else if (strcmp(token, "retry") == 0) {
			error = next_u32(rdr, "retry", &retry);
			extended = true;
		} else if (strcmp(token, "expire") == 0) {
			error = next_u32(rdr, "expire", &expire);
			extended = true;
		} else {
			pr_err("Unknown token: %s", token);
			return NULL;
		}
		if (error)
			return NULL;
	}

	if (extended) {
		if (!length_overridden)
			length = 24;
		pdu = create_pdu(24, version, pdu_type, _session, length);
		add_u32(pdu, 8, serial);
		add_u32(pdu, 12, refresh);
		add_u32(pdu, 16, retry);
		add_u32(pdu, 20, expire);
	} else {
		if (!length_overridden)
			length = 8;
		pdu = create_pdu(8, version, pdu_type, _session, length);
	}

	return pdu;
}

static struct pdu *
create_cache_reset_pdu(struct line_reader *rdr)
{
	return create_8pdu(rdr, 8, "zero", 0);
}

static struct pdu *
create_router_key_pdu(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t type = 9;
	uint8_t flags = 1;
	uint8_t zero = 0;
	uint32_t length = 0;
	bool length_overridden = false;
	unsigned char *ski = NULL;
	size_t ski_len = 0;
	uint32_t as = 0;
	unsigned char *spki = NULL;
	size_t spki_len = 0;
	char *token;
	struct pdu *pdu;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (is_type(token))
			error = next_u8(rdr, "pdu-type", &type);
		else if (strcmp(token, "flags") == 0)
			error = next_u8(rdr, "flags", &flags);
		else if (strcmp(token, "zero") == 0)
			error = next_u8(rdr, "zero", &zero);
		else if (strcmp(token, "length") == 0) {
			error = next_u32(rdr, "length", &length);
			length_overridden = true;
		} else if (strcmp(token, "ski") == 0)
			error = next_bytes(rdr, "ski", &ski, &ski_len);
		else if (strcmp(token, "as") == 0)
			error = next_u32(rdr, "as", &as);
		else if (strcmp(token, "spki") == 0)
			error = next_bytes(rdr, "spki", &spki, &spki_len);
		else {
			pr_err("Unknown token: %s", token);
			return NULL;
		}
		if (error)
			return NULL;
	}

	if (!length_overridden)
		length = 32 + spki_len;
	if (ski_len > 20) {
		pr_warn("The Subject Key Identifier is too long; truncating.");
		ski_len = 20;
	}

	pdu = create_pdu(32 + spki_len, version, type, (flags << 8) | zero, length);
	memcpy(pdu->buf + 8, ski, ski_len);
	free(ski);
	add_u32(pdu, 28, as);
	memcpy(pdu->buf + 32, spki, spki_len);
	free(spki);

	return pdu;
}

static struct pdu *
create_error_report_pdu(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t type = 10;
	uint16_t code = 1;
	uint32_t length = 0; /* "Length" field's value */
	bool length_overridden = false;
	uint32_t sublen = 0; /* "Length of Encapsulated PDU" field's value */
	bool sublen_overridden = false;
	struct pdu *subpdu = NULL;
	uint32_t msglen = 0; /* "Length of Arbitrary Text" field's value */
	bool msglen_overridden = false;
	char const *msg = NULL;

	char *token;
	size_t size; /* Actual PDU size */
	size_t subsize; /* Actual sub-PDU size */
	size_t msgsize; /* Actual text length */
	struct pdu *pdu;
	create_pdu_cb cb;
	int error = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, token, &_version);
		else if (is_type(token))
			error = next_u8(rdr, token, &type);
		else if (strcmp(token, "error-code") == 0)
			error = next_u16(rdr, token, &code);
		else if (strcmp(token, "length") == 0) {
			error = next_u32(rdr, token, &length);
			length_overridden = true;
		} else if (strcmp(token, "encapsulated-pdu-length") == 0) {
			error = next_u32(rdr, token, &sublen);
			sublen_overridden = true;
		} else if (strcmp(token, "encapsulated-pdu") == 0) {
			if (subpdu != NULL)
				free(subpdu);

			token = next_token(rdr);
			if (!token || !streq(token, "[")) {
				pr_err("Expected '[' after 'encapsulated-pdu'.");
				goto fail;
			}

			rdr->lvl++;
			token = next_token(rdr);
			if (!token) {
				pr_err("Expected PDU name after '['.");
				goto fail;
			}
			if ((cb = get_create_pdu_cb(token)) == NULL) {
				pr_err("Unknown PDU type: %s", token);
				goto fail;
			}
			subpdu = cb(rdr);
			if (!subpdu)
				goto fail;
			rdr->lvl--;

		} else if (strcmp(token, "error-text-length") == 0) {
			error = next_u32(rdr, token, &msglen);
			msglen_overridden = true;
		} else if (streq(token, "error-text"))
			error = next_string(rdr, token, &msg);
		else {
			pr_err("Unknown token: %s", token);
			goto fail;
		}
		if (error)
			goto fail;
	}

	subsize = subpdu ? subpdu->len : 0;
	if (!sublen_overridden)
		sublen = subsize;
	msgsize = msg ? strlen(msg) : 0;
	if (!msglen_overridden)
		msglen = msgsize;
	size = 16 + subsize + msgsize;
	if (!length_overridden)
		length = size;

	pdu = create_pdu(size, version, type, code, length);
	add_u32(pdu, 8, sublen);
	if (subpdu) {
		memcpy(pdu->buf + 12, subpdu->buf, subsize);
		free(subpdu);
	}
	add_u32(pdu, 12 + subsize, msglen);
	memcpy(pdu->buf + 16 + subsize, msg, msgsize);

	return pdu;

fail:	if (subpdu != NULL)
		free(subpdu);
	return NULL;
}

static struct pdu *
create_aspa_pdu_pdu(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t type = 11;
	uint8_t flags = 1;
	uint8_t zero = 0;
	uint32_t length = 12;
	bool length_overridden = false;
	uint32_t customer = 0;
	uint32_t *providers = NULL;
	size_t plen = 0;
	char *token;
	struct pdu *pdu = NULL;
	size_t i;
	int error;

	while ((token = next_token(rdr)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, token, &_version);
		else if (is_type(token))
			error = next_u8(rdr, token, &type);
		else if (strcmp(token, "flags") == 0)
			error = next_u8(rdr, token, &flags);
		else if (strcmp(token, "zero") == 0)
			error = next_u8(rdr, token, &zero);
		else if (strcmp(token, "length") == 0) {
			error = next_u32(rdr, token, &length);
			length_overridden = true;
		} else if (strcmp(token, "customer") == 0)
			error = next_u32(rdr, token, &customer);
		else if (strcmp(token, "providers") == 0)
			error = next_u32_array(rdr, token, &providers, &plen);
		else {
			pr_err("Unknown token: %s", token);
			goto end;
		}
		if (error)
			goto end;
	}

	if (!length_overridden)
		length = 12 + 4 * plen;

	pdu = create_pdu(12 + 4 * plen, _version, type,
	    (((unsigned int)flags) << 8) | ((unsigned int)zero), length);
	add_u32(pdu, 8, customer);
	for (i = 0; i < plen; i++)
		add_u32(pdu, 12 + 4 * i, providers[i]);

end:	free(providers);
	return pdu;
}

static struct pdu *
create_raw_pdu(struct line_reader *rdr)
{
	char *token;
	unsigned char *bytes;
	size_t n;
	struct pdu *pdu;

	pdu = pmalloc(sizeof(struct pdu));
	pdu->fd = -1;
	pdu->len = 0;
	pdu->offset = 0;

	while ((token = next_token(rdr)) != NULL) {
		if (streq(token, "<session>")) {
			bytes = pmalloc(2);
			n = __add_u16(bytes, atomic_load(&session));
		} else if (streq(token, "<serial>")) {
			bytes = pmalloc(4);
			n = __add_u32(bytes, serial);
		} else if (token2bytes(token, "raw", &bytes, &n) != 0) {
			goto fail;
		}

		if (pdu->len + n > PDUBUFLEN) {
			pr_err("Too many bytes: %zu > %u",
			    pdu->len + n, PDUBUFLEN);
			goto fail;
		}

		memcpy(pdu->buf + pdu->len, bytes, n);
		pdu->len += n;

		free(bytes);
		bytes = NULL;
	}

	return pdu;

fail:	free(bytes);
	free(pdu);
	return NULL;
}

static create_pdu_cb
get_create_pdu_cb(char const *name)
{
	if (streq(name, "serial-notify") || streq(name, "notify"))
		return create_serial_notify_pdu;
	if (streq(name, "serial-query") || streq(name, "serial"))
		return create_serial_query_pdu;
	if (streq(name, "reset-query") || streq(name, "reset"))
		return create_reset_query_pdu;
	if (streq(name, "cache-response") || streq(name, "response"))
		return create_cache_response_pdu;
	if (streq(name, "ipv4-prefix") || streq(name, "4"))
		return create_ipv4_prefix_pdu;
	if (streq(name, "ipv6-prefix") || streq(name, "6"))
		return create_ipv6_prefix_pdu;
	if (streq(name, "end-of-data") || streq(name, "eod"))
		return create_end_of_data_pdu;
	if (streq(name, "cache-reset"))
		return create_cache_reset_pdu;
	if (streq(name, "router-key") || streq(name, "rk"))
		return create_router_key_pdu;
	if (streq(name, "error-report") || streq(name, "error"))
		return create_error_report_pdu;
	if (streq(name, "aspa-pdu") || streq(name, "aspa"))
		return create_aspa_pdu_pdu;
	if (streq(name, "raw"))
		return create_raw_pdu;
	return NULL;
}

static void
send_pdu(struct pdu *pdu)
{
	print_pdu_cb printer;
	size_t i;

	if (!pdu)
		return;

	if (verbosity >= 2) {
		pr_trace("Sending %zu bytes.", pdu->len);

		pr_start(stdout, C_CYAN);
		printf("Sending: ");
		for (i = 0; i < pdu->len; i++) {
			printf("%02x", pdu->buf[i]);
			if ((i % 4) == 3)
				printf(" ");
		}
		pr_end(stdout);

		if (pdu->len >= 8) {
			printer = get_print_pdu_cb(pdu->buf[1]);
			if (printer && printer != print_pdu_unknown) {
				pr_start(stdout, C_CYAN);
				printf("Sending: ");
				pdu->offset = 8;
				printer(pdu, pdu->buf);
				printf("\n");
				pr_end(stdout);
			}
		}
	}

	full_write(pdu->buf, pdu->len);

	free(pdu);
}

static int
do_sleep(struct line_reader *rdr)
{
	char *token;
	unsigned long millis = 1000;
	struct timespec sleeptime;
	int error = 0;

	token = next_token(rdr);
	if (token) {
		error = str2ul("sleep", token, ULONG_MAX, &millis);
		if (error)
			return error;
	}

	sleeptime.tv_sec = millis / 1000;
	sleeptime.tv_nsec = (millis % 1000) * 1000000;

	if (nanosleep(&sleeptime, NULL) < 0) {
		error = errno;
		pr_err("Can't sleep: %s", strerror(error));
	}

	return error;
}

static int
send_infile_commands(void)
{
	struct line_reader rdr = { 0 };
	char *token;
	create_pdu_cb cb;
	int error;

	pr_trace("Ready.");

	while (getline(&rdr.line, &rdr.lsize, infile) != -1) {
		rdr.saveptr = NULL;
		rdr.first = true;
		rdr.lvl = 0;
		token = next_token(&rdr);
		if (!token)
			continue;

		if (strcmp(token, "version") == 0)
			next_u8(&rdr, "version", &version);
		else if (strcmp(token, "help") == 0)
			print_command_help();
		else if (strcmp(token, "sleep") == 0) {
			if (do_sleep(&rdr) == EINTR)
				break;
		} else if (strcmp(token, "exit") == 0)
			break;
		else if ((cb = get_create_pdu_cb(token)) != NULL)
			send_pdu(cb(&rdr));
		else
			pr_err("Unrecognized command: %s", token);
	}
	free(rdr.line);

	pr_trace("Canceling socket thread.");
	error = pthread_cancel(socket_thread);
	if (error)
		pr_err("Cound not cancel socket thread: %s. "
		    "IDK; try interrupting the process.",
		    strerror(error));

	if (feof(infile)) {
		pr_trace("End of input stream reached.");
		return 0;
	}
	if (ferror(infile)) {
		pr_err("Looks like there was some error reading the input stream.");
		return EINVAL;
	}

	return 0; /* "exit" requested*/
}

static uint16_t
assemble_u16(unsigned char *bytes)
{
	return (((unsigned int)bytes[0]) << 8) | (unsigned int)bytes[1];
}

static uint32_t
assemble_u32(unsigned char *bytes)
{
	return (((unsigned int)bytes[0]) << 24)
	     | (((unsigned int)bytes[1]) << 16)
	     | (((unsigned int)bytes[2]) << 8)
	     | ((unsigned int)bytes[3]);
}

static int
ensure_bytes(struct pdu *pdu, size_t need)
{
	ssize_t n;

	if (need > sizeof(pdu->buf))
		panic("Requested %zu bytes, buffer has %zu.",
		    need, sizeof(pdu->buf));

	if (pdu->len - pdu->offset >= need)
		return 0;

	if (pdu->fd < 0) {
		pr_warn("PDU is truncated.");
		return EINVAL;
	}

	pdu->len -= pdu->offset;
	memmove(pdu->buf, pdu->buf + pdu->offset, pdu->len);
	pdu->offset = 0;

	do {
		n = read(pdu->fd, pdu->buf + pdu->len,
		    sizeof(pdu->buf) - pdu->len);
		if (n < 0) {
			pr_err("Can't read PDU: %s", strerror(errno));
			return errno;
		}
		if (n == 0)
			return ENOENT;
		pdu->len += n;
	} while (pdu->len < need);

	return 0;
}

static int
read_u8(struct pdu *pdu, uint8_t *res)
{
	int error;

	error = ensure_bytes(pdu, 1);
	if (error)
		return error;

	*res = pdu->buf[pdu->offset++];
	return 0;
}

static int
read_u32(struct pdu *pdu, uint32_t *res)
{
	int error;

	error = ensure_bytes(pdu, 4);
	if (error)
		return error;

	*res = assemble_u32(&pdu->buf[pdu->offset]);
	pdu->offset += 4;
	return 0;
}

static int
read_bytes(struct pdu *pdu, unsigned char *res, size_t size)
{
	int error;

	error = ensure_bytes(pdu, size);
	if (error)
		return error;

	memcpy(res, &pdu->buf[pdu->offset], size);
	pdu->offset += size;
	return 0;

}

static int
print_u8(struct pdu *pdu, char const *pfx, size_t *remainder)
{
	uint8_t u8;
	int error;

	error = read_u8(pdu, &u8);
	if (error)
		return error;

	printf("%s %u ", pfx, u8);

	*remainder -= 1;
	return 0;
}

static int
print_u32(struct pdu *pdu, char const *pfx, size_t *remainder)
{
	uint32_t u32;
	int error;

	error = read_u32(pdu, &u32);
	if (error)
		return error;

	if (pfx)
		printf("%s %u ", pfx, u32);
	else
		printf("%u ", u32);

	*remainder -= 4;
	return 0;
}

static void
__print_addr4(unsigned char *buf)
{
	struct in_addr addr;
	char addr_strbuf[INET_ADDRSTRLEN];
	char const *addr_str;

	addr.s_addr = htonl(assemble_u32(buf));
	addr_str = inet_ntop(AF_INET, &addr, addr_strbuf, sizeof(addr_strbuf));
	if (!addr_str)
		pr_warn("Cannot convert addr4 to string: %s", strerror(errno));
	printf("%s ", addr_str ? addr_str : "null");
}

static int
print_addr4(struct pdu *pdu, char const *pfx, size_t *remainder)
{
	unsigned char buf[4];
	int error;

	error = read_bytes(pdu, buf, 4);
	if (error)
		return error;

	printf("%s ", pfx);
	__print_addr4(buf);

	*remainder -= 4;
	return 0;
}

static void
__print_addr6(unsigned char *buf)
{
	char addr_strbuf[INET6_ADDRSTRLEN];
	char const *addr_str;

	addr_str = inet_ntop(AF_INET6, buf, addr_strbuf, sizeof(addr_strbuf));
	if (!addr_str)
		pr_warn("Cannot convert addr6 to string: %s", strerror(errno));
	printf("%s ", addr_str ? addr_str : "null");
}

static int
print_addr6(struct pdu *pdu, char const *pfx, size_t *remainder)
{
	unsigned char buf[16];
	int error;

	error = read_bytes(pdu, buf, 16);
	if (error)
		return error;

	printf("%s ", pfx);
	__print_addr6(buf);

	*remainder -= 16;
	return 0;
}

static int
print_str(struct pdu *pdu, char const *pfx, size_t *remainder)
{
	uint32_t len;
	size_t room;
	size_t printable;
	int error;

	error = read_u32(pdu, &len);
	if (error)
		return error;
	printf("%s-length %u ", pfx, len);
	*remainder -= 4;

	if (*remainder < len)
		len = *remainder;
	*remainder -= len;

	if (len > 0) {
		printf("%s ", pfx);
		do {
			error = ensure_bytes(pdu,
			    len < sizeof(pdu->buf) ? len : sizeof(pdu->buf));
			if (error)
				return error;

			room = pdu->len - pdu->offset;
			printable = (room < len) ? room : len;
			printf("%.*s", (int)printable, &pdu->buf[pdu->offset]);

			pdu->offset += printable;
			len -= printable;
		} while (len > 0);
		printf(" ");
	}

	return 0;
}

static int print_pdu(struct pdu *, unsigned char *);

/* Result will be the payload length, *ACCORDING TO THE HEADER*. */
static size_t
print_hdr1(unsigned char *hdr, char const *key3)
{
	uint32_t length;

	length = assemble_u32(hdr + 4);
	printf("version %u %s %u length %u ",
	    hdr[0],
	    key3, assemble_u16(hdr + 2),
	    length);

	return (length >= 8) ? (length - 8) : 0;
}

static size_t
print_hdr2(unsigned char *hdr, char const *key3, char const *key4)
{
	uint32_t length;

	length = assemble_u32(hdr + 4);
	printf("version %u %s %u %s %u length %u ",
	    hdr[0],
	    key3, hdr[2],
	    key4, hdr[3],
	    length);

	return (length >= 8) ? (length - 8) : 0;
}

static void
__print_hex(unsigned char *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		printf("%02x", buf[i]);
}

static int
print_hex(struct pdu *pdu, char const *pfx, size_t len)
{
	size_t room;
	size_t printable;
	int error;

	if (len == 0)
		return 0;

	if (pfx)
		printf("%s ", pfx);
	while (len > 0) {
		error = ensure_bytes(pdu,
		    len < sizeof(pdu->buf) ? len : sizeof(pdu->buf));
		if (error)
			return error;

		room = pdu->len - pdu->offset;
		printable = (room < len) ? room : len;
		__print_hex(&pdu->buf[pdu->offset], printable);
		pdu->offset += printable;
		len -= printable;
	};
	printf(" ");

	return 0;
}

static int
print_remainder(struct pdu *pdu, size_t remainder)
{
	return print_hex(pdu, "remainder", remainder);
}

static int
print_pdu_serial_notify(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("serial-notify  ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "serial", &remainder);
	if (error)
		return error;

done:	return print_remainder(pdu, remainder);
}

static int
print_pdu_serial_query(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("serial-query   ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "serial", &remainder);
	if (error)
		return error;

done:	return print_remainder(pdu, remainder);
}

static int
print_pdu_reset_query(struct pdu *pdu, unsigned char *hdr)
{
	printf("reset-query    ");
	return print_remainder(pdu, print_hdr1(hdr, "zero"));
}

static int
print_pdu_cache_response(struct pdu *pdu, unsigned char *hdr)
{
	printf("cache-response ");
	return print_remainder(pdu, print_hdr1(hdr, "session"));
}

static int
print_pdu_ipv4_prefix(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("ipv4-prefix    ");
	remainder = print_hdr1(hdr, "zero1");

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "flags", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "plen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "maxlen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "zero2", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_addr4(pdu, "prefix", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "as", &remainder);
	if (error)
		return error;

done:	return print_remainder(pdu, remainder);
}

static int
print_pdu_ipv6_prefix(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("ipv6-prefix    ");
	remainder = print_hdr1(hdr, "zero1");

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "flags", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "plen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "maxlen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8(pdu, "zero2", &remainder);
	if (error)
		return error;

	if (remainder < 16)
		goto done;
	error = print_addr6(pdu, "prefix", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "as", &remainder);
	if (error)
		return error;

done:	return print_remainder(pdu, remainder);
}

static int
print_pdu_end_of_data(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("end-of-data    ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "serial", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "refresh", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "retry", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32(pdu, "expire", &remainder);
	if (error)
		return error;

done:	return print_remainder(pdu, remainder);
}

static int
print_pdu_cache_reset(struct pdu *pdu, unsigned char *hdr)
{
	printf("cache-reset    ");
	return print_remainder(pdu, print_hdr1(hdr, "zero"));
}

static int
print_pdu_router_key(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("router-key     ");
	remainder = print_hdr2(hdr, "flags", "zero");

	if (remainder < 24)
		goto end;
	error = print_hex(pdu, "ski", 20);
	if (error)
		return error;
	remainder -= 20;

	if (remainder < 4)
		goto end;
	error = print_u32(pdu, "as", &remainder);
	if (error)
		return error;

	return print_hex(pdu, "spki", remainder);

end:	return print_remainder(pdu, remainder);
}

static int
print_pdu_aspa_pdu(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("aspa-pdu       ");
	remainder = print_hdr2(hdr, "flags", "zero");

	if (remainder < 4)
		goto end;
	error = print_u32(pdu, "customer", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto end;
	printf("providers [ ");
	do {
		error = print_u32(pdu, NULL, &remainder);
		if (error)
			return error;
	} while (remainder >= 4);
	printf("] ");

end:	return print_remainder(pdu, remainder);
}

static int
print_subpdu(struct pdu *pdu, size_t remainder, uint32_t sublen)
{
	struct pdu subpdu;
	unsigned char subhdr[8];
	size_t i;
	int error;

	if (sublen < 8)
		goto hex;

	if (remainder < 8)
		goto hex;
	error = read_bytes(pdu, subhdr, sizeof(subhdr));
	if (error)
		return error;
	if (assemble_u32(&subhdr[4]) != sublen || remainder < sublen)
		goto hdrhex;

	subpdu.fd = -1;
	if (read_bytes(pdu, subpdu.buf, sublen - 8) != 0)
		goto hdrhex;
	subpdu.len = sublen - 8;
	subpdu.offset = 0;

	printf("encapsulated-pdu [ ");
	error = print_pdu(&subpdu, subhdr);
	printf("] ");

	return error;

hex:	return print_hex(pdu, "encapsulated-pdu", sublen);

hdrhex:	printf("encapsulated-pdu [ ");
	for (i = 0; i < 8; i++)
		printf("%02x", subhdr[i]);
	if (sublen > 8)
		print_hex(pdu, NULL, sublen - 8);
	else
		printf(" ");
	printf("] ");
	return 0;
}

static int
print_pdu_error_report(struct pdu *pdu, unsigned char *hdr)
{
	size_t remainder;
	uint32_t sublen;
	int error;

	printf("error-report   ");
	remainder = print_hdr1(hdr, "error-code");

	if (remainder < 4)
		goto end;
	error = read_u32(pdu, &sublen);
	if (error)
		return error;
	printf("encapsulated-pdu-length %u ", sublen);
	remainder -= 4;

	error = print_subpdu(pdu, remainder, sublen);
	if (error)
		return error;

	remainder -= sublen;
	if (remainder < 4)
		goto end;
	error = print_str(pdu, "error-text", &remainder);
	if (error)
		return error;

end:	return print_remainder(pdu, remainder);
}

static int
print_pdu_unknown(struct pdu *pdu, unsigned char *hdr)
{
	printf("unknown        ");
	__print_hex(hdr, 8);
	printf(" ");
	return print_hex(pdu, "remainder", pdu->len);
}

static print_pdu_cb
get_print_pdu_cb(unsigned char type)
{
	switch (type) {
	case 0:  return print_pdu_serial_notify;
	case 1:  return print_pdu_serial_query;
	case 2:  return print_pdu_reset_query;
	case 3:  return print_pdu_cache_response;
	case 4:  return print_pdu_ipv4_prefix;
	case 6:  return print_pdu_ipv6_prefix;
	case 8:  return print_pdu_cache_reset;
	case 7:  return print_pdu_end_of_data;
	case 9:  return print_pdu_router_key;
	case 10: return print_pdu_error_report;
	case 11: return print_pdu_aspa_pdu;
	default: return print_pdu_unknown;
	}
}

static int
print_rapport_vrp4(struct pdu *pdu, unsigned char *hdr)
{
	uint32_t len;
	unsigned char payload[12];
	int error;

	len = assemble_u32(&hdr[4]);
	if (len != 20) {
		pr_err("IPv4 PDU length != 20: %u", len);
		return EINVAL;
	}

	error = read_bytes(pdu, payload, sizeof(payload));
	if (error)
		return error;

	switch (payload[0]) {
	case 0:
		printf("VRP-\t");
		break;
	case 1:
		printf("VRP+\t");
		break;
	default:
		printf("VRP!\t");
	}

	__print_addr4(&payload[4]);
	printf("/%u-%u => %u",
	   payload[1],
	   payload[2],
	   assemble_u32(&payload[8]));
	return 0;
}

static int
print_rapport_vrp6(struct pdu *pdu, unsigned char *hdr)
{
	uint32_t len;
	unsigned char payload[24];
	int error;

	len = assemble_u32(&hdr[4]);
	if (len != 32) {
		pr_err("IPv6 PDU length != 32: %u", len);
		return EINVAL;
	}

	error = read_bytes(pdu, payload, sizeof(payload));
	if (error)
		return error;

	switch (payload[0]) {
	case 0:
		printf("VRP-\t");
		break;
	case 1:
		printf("VRP+\t");
		break;
	default:
		printf("VRP!\t");
	}

	__print_addr6(&payload[4]);
	printf("/%u-%u => %u",
	    payload[1],
	    payload[2],
	    assemble_u32(&payload[20]));
	return 0;
}

static int
print_rapport_errpdu(struct pdu *pdu, unsigned char *hdr)
{
	size_t len, sublen, msglen;
	unsigned char buf[1024];
	unsigned char *cursor;
	int error;

	len = assemble_u32(&hdr[4]);
	if (len < 16) {
		pr_err("Error Report PDU length is too small: %zu", len);
		return EINVAL;
	}
	len -= 8;
	if (len > 1024) {
		pr_err("Error Report PDU payload length is too big: %zu", len);
		return EINVAL;
	}

	error = read_bytes(pdu, buf, len);
	if (error)
		return error;

	sublen = assemble_u32(buf);
	if (sublen > len - 8) {
		pr_err("Bad Error Report lengths: %zu, %zu, ?",
		    len + 8, sublen);
		return error;
	}

	cursor = buf + 4 + sublen;
	msglen = assemble_u32(cursor);
	if (8 + sublen + msglen != len) {
		pr_err("Bad Error Report lengths: %zu, %zu, %zu",
		    len + 8, sublen, msglen);
	}

	pr_err("Error Report: %.*s", (int)msglen, (char *)(cursor + 4));
	return 0;
}

static int
print_rapport_aspa(struct pdu *pdu, unsigned char *hdr)
{
	uint32_t len;
	unsigned char buf[4];
	uint32_t p;
	int error;

	len = assemble_u32(&hdr[4]);
	if (len < 12) {
		pr_err("ASPA PDU length is too small: %u", len);
		return EINVAL;

	}
	if ((len % 4) != 0) {
		pr_err("ASPA PDU length is not a multiple of 4: %u", len);
		return EINVAL;
	}
	len -= 12;

	error = read_bytes(pdu, buf, sizeof(buf));
	if (error)
		return error;

	printf("ASPA\t%u:[", assemble_u32(buf));
	for (p = 0; p < len; p += 4) {
		error = read_bytes(pdu, buf, sizeof(buf));
		if (error)
			return error;
		printf("%u", assemble_u32(buf));
		if (p != len - 4)
			printf(",");
	}
	printf("]");

	return 0;
}

static int
skip_pdu(struct pdu *pdu, unsigned char *hdr)
{
	uint32_t len;
	size_t room;
	size_t waste;
	int error;

	len = assemble_u32(&hdr[4]);
	if (len < 8) {
		pr_err("PDU length too small: %u", len);
		return EINVAL;
	}
	len -= 8;

	room = pdu->len - pdu->offset;
	if (room >= len) {
		pdu->offset += len;
		return 0;
	}

	pdu->len = 0;
	pdu->offset = 0;

	for (len -= room; len != 0; len -= waste) {
		waste = len < sizeof(pdu->buf) ? len : sizeof(pdu->buf);
		error = ensure_bytes(pdu, waste);
		if (error)
			return error;
		pdu->len = 0;
	}

	return 0;
}

static int
print_pdu(struct pdu *pdu, unsigned char *hdr)
{
	int error = EINVAL;

	/* Pre-print */
	/* TODO happening for internal PDUs too */
	switch (hdr[1]) {
	case 0:
	case 1:
	case 3:
	case 7:
		atomic_store(&session, assemble_u16(&hdr[2]));
	}

	switch (format) {
	case OF_PDU:
		error = get_print_pdu_cb(hdr[1])(pdu, hdr);
		break;

	case OF_RAPPORT:
		switch (hdr[1]) {
		case 4:  error = print_rapport_vrp4(pdu, hdr);		break;
		case 6:  error = print_rapport_vrp6(pdu, hdr);		break;
		case 10: error = print_rapport_errpdu(pdu, hdr);	break;
		case 11: error = print_rapport_aspa(pdu, hdr);		break;
		case 9:  /* Format still undecided */
		default: return skip_pdu(pdu, hdr);
		}
	}

	return error;
}

static bool
is_terminating_pdu(unsigned char type)
{
	return type != 0 && type != 1 && type != 2 && type != 3 && type != 4
	    && type != 5 && type != 6 && type != 9 && type != 11;
}

static void
print_server_response(void)
{
	struct pdu pdu = { .fd = rtrfd };
	unsigned char hdr[8];

	do {
		if (read_bytes(&pdu, hdr, sizeof(hdr)) != 0)
			return;
		pr_trace("PDU received.");
		if (print_pdu(&pdu, hdr) != 0)
			return;
		printf("\n");
	} while (!is_terminating_pdu(hdr[1]));
}

static void *
handle_server_pdus(void *arg)
{
	struct pdu pdu = { .fd = rtrfd };
	unsigned char hdr[8];
	int error;

	do {
		if (read_bytes(&pdu, hdr, sizeof(hdr)) != 0)
			return NULL;
		pr_trace("PDU received.");
		error = print_pdu(&pdu, hdr);

		printf("\n");
		/*
		 * Newline does not always imply a flush, but we do need it
		 * because interactive mode often terminates by SIGTERM.
		 */
		fflush(stdout);

		if (error)
			return NULL;
	} while (true);
}

static void
start_socket_listener(void)
{
	int error;

	pr_trace("Starting RTR socket listener thread.");
	error = pthread_create(&socket_thread, NULL, handle_server_pdus, NULL);
	if (error)
		panic("pthread_create(): %s", strerror(error));
}

static void
stop_socket_listener(void)
{
	int error;

	pr_trace("Joining RTR socket listener thread.");;
	error = pthread_join(socket_thread, NULL);
	if (error)
		pr_err("pthread_join(): %s", strerror(error));
}

int
main(int argc, char **argv)
{
	struct pdu *pdu;
	int error = 0;

	infile = stdin;

	register_signal_handlers();

	parse_options(argc, argv);

	if (strcmp(action, "reset") == 0) {
		connect_socket();
		send_pdu(create_pdu(8, version, 2, 0, 8));
		print_server_response();
		close_socket();

	} else if (strcmp(action, "serial") == 0) {
		connect_socket();
		pdu = create_pdu(12, version, 1, atomic_load(&session), 12);
		add_u32(pdu, 8, serial);
		send_pdu(pdu);
		print_server_response();
		close_socket();

	} else if (strcmp(action, "interactive") == 0) {
		connect_socket();
		start_socket_listener();
		open_infile();
		error = send_infile_commands();
		close_infile();
		stop_socket_listener();
		close_socket();

	} else {
		pr_err("Unknown action: %s", action);
		error = EINVAL;
	}

	return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
