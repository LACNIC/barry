#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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

#include "print.h"

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
char const *input;

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
};

static char *
next_token(struct line_reader *rdr, bool first)
{
	char *token;
	token = strtok_r(first ? rdr->line : NULL, " \t\n", &rdr->saveptr);
	pr_trace("Received token: %s", token);
	return token;
}

static void
print_help(void)
{
	printf("Usage:\n");
	printf("  barry-rtr [%s-h%s] [%s-v%s[%sv%s]] [%s-c%s] [%s-f%s<format>%s] [%s-i%s<input-source>%s] \\\n", flg, rst, flg, rst, flg, rst, flg, rst, flg, var, rst, flg, var, rst);
	printf("      [%s-V%s<version>%s] [%s-s%s<session>%s] [%s-l%s<serial>%s] \\\n", flg, var, rst, flg, var, rst, flg, var, rst);
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
	printf("  %s-V%s sets RTR version number (Default: %u)\n", flg, rst, version);
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
	printf("%sversion%s %s<VER>%s\n", cmd, rst, var, rst);
	printf("  Sets the default RTR version number sent by all subsequent PDUs.\n");
	printf("  %s<VER>%s: unsigned 8-bit integer. Default: %s--version%s (%s-V%s)\n", var, rst, flg, rst, flg, rst);
	printf("\n");
	printf("%sreset-query%s [version %s<RV>%s] [pdu-type %s<RT>%s] [zero %s<RZ>%s] [length %s<RL>%s]\n",
	    cmd, rst, var, rst, var, rst, var, rst, var, rst);
	printf("  Sends a Reset Query PDU to the server. Arguments are header fields.\n");
	printf("  %s<RV>%s: unsigned  8-bit integer. Default: %s<VER>%s\n", var, rst, var, rst);
	printf("  %s<RT>%s: unsigned  8-bit integer. Default: 2\n", var, rst);
	printf("  %s<RZ>%s: unsigned 16-bit integer. Default: 0\n", var, rst);
	printf("  %s<RL>%s: unsigned 32-bit integer. Default: 8\n", var, rst);
	printf("\n");
	printf("%sserial-query%s [version %s<SV>%s] [pdu-type %s<ST>%s] [session %s<SS>%s] \\\n",
	    cmd, rst, var, rst, var, rst, var, rst);
	printf("             [length %s<SL>%s] [serial %s<SE>%s]\n", var, rst, var, rst);
	printf("  Sends a Serial Query PDU to the server. Arguments are header fields.\n");
	printf("  %s<SV>%s: unsigned  8-bit integer. Default: %s<VER>%s\n", var, rst, var, rst);
	printf("  %s<ST>%s: unsigned  8-bit integer. Default: 1\n", var, rst);
	printf("  %s<SS>%s: unsigned 16-bit integer. Default: 0\n", var, rst);
	printf("    The default value is overridden by the actual session number\n");
	printf("    whenever the server announces it.\n");
	printf("  %s<SL>%s: unsigned 32-bit integer. Default: 12\n", var, rst);
	printf("  %s<SE>%s: unsigned 32-bit integer. Default: 0\n", var, rst);
	printf("\n");
	printf("%shelp%s\n", cmd, rst);
	printf("  Prints this wall of text.\n");
	printf("\n");
	printf("%sexit%s\n", cmd, rst);
	printf("  Quits.\n");
}

static int
str2ul(char const *what, char const *str, unsigned long max, unsigned long *ul)
{
	unsigned long v;
	char *tailptr;

	if (!str) {
		pr_err("Expected token after '%s'.", what);
		return EINVAL;
	}

	errno = 0;
	v = strtoul(str, &tailptr, 10);
	if (errno) {
		pr_err("Cannot convert %s to int: %s", what, strerror(errno));
		return EINVAL;
	}
	if (str == tailptr) {
		pr_err("Cannot convert %s to int.", what);
		return EINVAL;
	}
	if (v > max) {
		pr_err("%s cannot be > %lu.", what, max);
		return EINVAL;
	}

	*ul = v;
	return 0;
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
	return parse_u8(what, next_token(rdr, false), value);
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
	return parse_u16(what, next_token(rdr, false), value);
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
	return parse_u32(what, next_token(rdr, false), value);
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
	case OF_RAPPORT:	return "pdu";
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
			pr_err("socket(%s, %s): %s\n", server, port,
			    strerror(errno));
			continue;
		}
		if (connect(rtrfd, alt->ai_addr, alt->ai_addrlen) != -1)
			break; /* Success */

		pr_err("connect(%s, %s): %s\n", server, port, strerror(errno));
		close(rtrfd);
	}

	freeaddrinfo(alternatives);

	if (!alt)
		panic("None of the addrinfo candidates could connect.\n");
}

static void
close_socket(void)
{
	pr_trace("Closing RTR socket.");
	close(rtrfd);
}

static void
add_u8(unsigned char *msg, uint8_t u8)
{
	msg[0] = u8;
}

static void
add_u16(unsigned char *msg, uint16_t u16)
{
	msg[0] = (u16 >> 8) & 0xFFu;
	msg[1] = (u16 >> 0) & 0xFFu;
}

static void
add_u32(unsigned char *msg, uint32_t u32)
{
	msg[0] = (u32 >> 24) & 0xFFu;
	msg[1] = (u32 >> 16) & 0xFFu;
	msg[2] = (u32 >>  8) & 0xFFu;
	msg[3] = (u32 >>  0) & 0xFFu;
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

static void
__send_reset_query(uint8_t version, uint8_t type, uint16_t zero, uint32_t len)
{
	unsigned char msg[8];

	add_u8(&msg[0], version);
	add_u8(&msg[1], type);
	add_u16(&msg[2], zero);
	add_u32(&msg[4], len);

	pr_trace("Sending Reset Query PDU.");
	full_write(msg, sizeof(msg));
}

static void
send_reset_query(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t pdu_type = 2;
	uint16_t zero = 0;
	uint32_t length = 8;
	char *token;
	int error = 0;

	while ((token = next_token(rdr, false)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (strcmp(token, "pdu-type") == 0)
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, "zero") == 0)
			error = next_u16(rdr, "zero", &zero);
		else if (strcmp(token, "length") == 0)
			error = next_u32(rdr, "length", &length);
		else {
			pr_err("Unknown token: %s", token);
			return;
		}
		if (error)
			return;
	}

	__send_reset_query(_version, pdu_type, zero, length);
}

static void
__send_serial_query(uint8_t version, uint8_t type, uint16_t session,
    uint32_t len, uint32_t serial)
{
	unsigned char msg[12];

	add_u8(&msg[0], version);
	add_u8(&msg[1], type);
	add_u16(&msg[2], session);
	add_u32(&msg[4], len);
	add_u32(&msg[8], serial);

	pr_trace("Sending Serial Query PDU.");
	full_write(msg, sizeof(msg));
}

static void
send_serial_query(struct line_reader *rdr)
{
	uint8_t _version = version;
	uint8_t pdu_type = 1;
	uint16_t _session = atomic_load(&session);
	uint32_t length = 12;
	uint32_t serial = 0;
	char *token;
	int error = 0;

	while ((token = next_token(rdr, false)) != NULL) {
		if (strcmp(token, "version") == 0)
			error = next_u8(rdr, "version", &_version);
		else if (strcmp(token, "pdu-type") == 0)
			error = next_u8(rdr, "pdu-type", &pdu_type);
		else if (strcmp(token, "session") == 0)
			error = next_u16(rdr, "session", &_session);
		else if (strcmp(token, "length") == 0)
			error = next_u32(rdr, "length", &length);
		else if (strcmp(token, "serial") == 0)
			error = next_u32(rdr, "serial", &serial);
		else {
			pr_err("Unknown token: %s", token);
			return;
		}
		if (error)
			return;
	}

	__send_serial_query(_version, pdu_type, _session, length, serial);
}

static int
send_infile_commands(void)
{
	struct line_reader rdr = { 0 };
	char *token;
	int error;

	pr_trace("Ready.");

	while (getline(&rdr.line, &rdr.lsize, infile) != -1) {
		token = next_token(&rdr, true);
		if (!token)
			continue;

		if (strcmp(token, "version") == 0)
			next_u8(&rdr, "version", &version);
		else if (strcmp(token, "reset-query") == 0 || strcmp(token, "reset") == 0)
			send_reset_query(&rdr);
		else if (strcmp(token, "serial-query") == 0 || strcmp(token, "serial") == 0)
			send_serial_query(&rdr);
		else if (strcmp(token, "help") == 0)
			print_command_help();
		else if (strcmp(token, "exit") == 0)
			break;
		else
			pr_err("Unrecognized command.");
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

static int
full_read(unsigned char *buf, size_t size)
{
	ssize_t consumed;
	int error;

	do {
		consumed = read(rtrfd, buf, size);
		if (consumed < 0) {
			error = errno;
			pr_err("Cannot read server response: %s",
			    strerror(error));
			return error;
		}
		buf += consumed;
		size -= consumed;
	} while (size > 0);

	return 0;
}

static uint8_t
assemble_u8(unsigned char *bytes)
{
	return bytes[0];
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
print_u8(char const *pfx, size_t *remainder)
{
	unsigned char buf[1];
	int error;

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	printf("%s %u ", pfx, assemble_u8(buf));
	*remainder -= 1;
	return 0;
}

static int
print_u32(char const *pfx, size_t *remainder)
{
	unsigned char buf[4];
	int error;

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	if (pfx)
		printf("%s %u ", pfx, assemble_u32(buf));
	else
		printf("%u ", assemble_u32(buf));
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
print_addr4(char const *pfx, size_t *remainder)
{
	unsigned char buf[4];
	int error;

	error = full_read(buf, sizeof(buf));
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
	struct in6_addr addr;
	char addr_strbuf[INET6_ADDRSTRLEN];
	char const *addr_str;

	addr.s6_addr32[0] = htonl(assemble_u32(buf));
	addr.s6_addr32[1] = htonl(assemble_u32(&buf[4]));
	addr.s6_addr32[2] = htonl(assemble_u32(&buf[8]));
	addr.s6_addr32[3] = htonl(assemble_u32(&buf[12]));
	addr_str = inet_ntop(AF_INET6, &addr, addr_strbuf, sizeof(addr_strbuf));
	if (!addr_str)
		pr_warn("Cannot convert addr6 to string: %s", strerror(errno));
	printf("%s ", addr_str ? addr_str : "null");
}

static int
print_addr6(char const *pfx, size_t *remainder)
{
	unsigned char buf[16];
	int error;

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	printf("%s ", pfx);
	__print_addr6(buf);

	*remainder -= 16;
	return 0;
}

static int
print_str(char const *pfx, size_t *remainder)
{
	unsigned char buf[1024];
	uint32_t len;
	ssize_t consumed;
	int error;

	error = full_read(buf, 4);
	if (error)
		return error;

	len = assemble_u32(buf);
	printf("%s-length %u ", pfx, len);
	*remainder -= 4;

	if (*remainder < len)
		len = *remainder;
	*remainder -= len;

	if (len > 0) {
		printf("%s ", pfx);
		while (len > 0) {
			consumed = read(rtrfd, buf, 1024 < len ? 1024 : len);
			if (consumed < 0) {
				error = errno;
				pr_err("Cannot read server response: %s",
				    strerror(error));
				return error;
			}
			printf("%.*s", (int)consumed, buf);
			len -= consumed;
		}
		printf(" ");
	}

	return 0;
}

static int print_pdu(unsigned char *);

/* Returns the payload length */
static size_t
print_hdr1(unsigned char *bytes, char const *field3_what)
{
	uint8_t v;
	uint16_t field3;
	uint32_t length;

	v = assemble_u8(&bytes[0]);
	field3 = assemble_u16(&bytes[2]);
	length = assemble_u32(&bytes[4]);
	printf("version %u %s %u length %u ", v, field3_what, field3, length);

	return (length >= 8) ? (length - 8) : 0;
}

static size_t
print_hdr2(unsigned char *bytes, char const *field3_what, char const *field4_what)
{
	uint32_t length;

	length = assemble_u32(&bytes[4]);
	printf("version %u %s %u %s %u length %u ",
	    assemble_u8(&bytes[0]),
	    field3_what, assemble_u8(&bytes[2]),
	    field4_what, assemble_u8(&bytes[3]),
	    length);

	return (length >= 8) ? (length - 8) : 0;
}

static int
print_hex(char const *pfx, size_t len)
{
	unsigned char buf[1024];
	ssize_t consumed;
	ssize_t i;
	int error;

	if (len == 0)
		return 0;

	printf("%s ", pfx);
	while (len > 0) {
		consumed = read(rtrfd, buf, len < sizeof(buf) ? len : sizeof(buf));
		if (consumed < 0) {
			error = errno;
			pr_err("Cannot read server response: %s",
			    strerror(error));
			return error;
		}
		for (i = 0; i < consumed; i++)
			printf("%02x", buf[i]);
		len -= consumed;
	}

	return 0;
}

static int
print_remainder(size_t remainder)
{
	return print_hex("remainder", remainder);
}

static int
print_pdu_serial_notify(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("serial-notify  ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32("serial", &remainder);
	if (error)
		return error;

done:	return print_remainder(remainder);
}

static int
print_pdu_serial_query(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("serial-query   ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32("serial", &remainder);
	if (error)
		return error;

done:	return print_remainder(remainder);
}

static int
print_pdu_reset_query(unsigned char *hdr)
{
	printf("reset-query    ");
	return print_remainder(print_hdr1(hdr, "zero"));
}

static int
print_pdu_cache_response(unsigned char *hdr)
{
	printf("cache-response ");
	return print_remainder(print_hdr1(hdr, "session"));
}

static int
print_pdu_ipv4_prefix(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("ipv4-prefix    ");
	remainder = print_hdr1(hdr, "zero");

	if (remainder < 1)
		goto done;
	error = print_u8("flags", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("plen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("maxlen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("zero", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_addr4("prefix", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32("as", &remainder);
	if (error)
		return error;

done:	return print_remainder(remainder);
}

static int
print_pdu_ipv6_prefix(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("ipv6-prefix    ");
	remainder = print_hdr1(hdr, "zero");

	if (remainder < 1)
		goto done;
	error = print_u8("flags", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("plen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("maxlen", &remainder);
	if (error)
		return error;

	if (remainder < 1)
		goto done;
	error = print_u8("zero", &remainder);
	if (error)
		return error;

	if (remainder < 16)
		goto done;
	error = print_addr6("prefix", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32("as", &remainder);
	if (error)
		return error;

done:	return print_remainder(remainder);
}

static int
print_pdu_end_of_data(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("end-of-data    ");
	remainder = print_hdr1(hdr, "session");

	if (remainder < 4)
		goto done;
	error = print_u32("serial", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32("refresh", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32("retry", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto done;
	error = print_u32("expire", &remainder);
	if (error)
		return error;

done:	return print_remainder(remainder);
}

static int
print_pdu_cache_reset(unsigned char *hdr)
{
	printf("cache-reset    ");
	return print_remainder(print_hdr1(hdr, "zero"));
}

static int
print_pdu_router_key(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("router-key     ");
	remainder = print_hdr2(hdr, "flags", "zero");

	if (remainder < 24)
		goto end;
	error = print_hex("ski", 24);
	if (error)
		return error;
	remainder -= 24;

	if (remainder < 4)
		goto end;
	error = print_u32("as", &remainder);
	if (error)
		return error;

	return print_hex("spki", remainder);

end:	return print_remainder(remainder);
}

static int
print_pdu_aspa_pdu(unsigned char *hdr)
{
	size_t remainder;
	int error;

	printf("aspa-pdu       ");
	remainder = print_hdr2(hdr, "flags", "zero");

	if (remainder < 4)
		goto end;
	error = print_u32("customer", &remainder);
	if (error)
		return error;

	if (remainder < 4)
		goto end;
	printf("providers [ ");
	do {
		error = print_u32(NULL, &remainder);
		if (error)
			return error;
	} while (remainder >= 4);
	printf("]");

end:	return print_remainder(remainder);
}

static int
print_pdu_error_report(unsigned char *hdr)
{
	size_t remainder, sublen;
	unsigned char subhdr[1024];
	int error;

	printf("error-report   ");
	remainder = print_hdr1(hdr, "error-code");

	if (remainder < 4)
		goto end;
	error = print_u32("encapsulated-pdu-length", &remainder);
	if (error)
		return error;

	if (remainder < 8)
		goto end;
	error = full_read(subhdr, 8);
	if (error)
		return error;
	sublen = assemble_u32(&subhdr[4]);
	if (remainder < sublen)
		goto end;
	printf("encapsulated-pdu [");
	error = print_pdu(subhdr);
	if (error)
		return error;
	printf("] ");
	remainder -= sublen;

	if (remainder < 4)
		goto end;
	error = print_str("error-text", &remainder);
	if (error)
		return error;

end:	return print_remainder(remainder);
}

static int
print_pdu_unknown(unsigned char *hdr)
{
	printf("unknown        ");
	return print_remainder(print_hdr1(hdr, "?"));
}

static int
print_rapport_vrp4(unsigned char *hdr)
{
	uint32_t len;
	unsigned char payload[12];
	int error;

	len = assemble_u32(&hdr[4]);
	if (len != 20) {
		pr_err("IPv4 PDU length != 20: %u", len);
		return EINVAL;
	}

	error = full_read(payload, sizeof(payload));
	if (error)
		return error;

	switch (assemble_u8(&payload[0])) {
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
	    assemble_u8(&payload[1]),
	    assemble_u8(&payload[2]),
	    assemble_u32(&payload[8]));
	return 0;
}

static int
print_rapport_vrp6(unsigned char *hdr)
{
	uint32_t len;
	unsigned char payload[24];
	int error;

	len = assemble_u32(&hdr[4]);
	if (len != 32) {
		pr_err("IPv6 PDU length != 32: %u", len);
		return EINVAL;
	}

	error = full_read(payload, sizeof(payload));
	if (error)
		return error;

	switch (assemble_u8(&payload[0])) {
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
	    assemble_u8(&payload[1]),
	    assemble_u8(&payload[2]),
	    assemble_u32(&payload[20]));
	return 0;
}

static int
print_rapport_errpdu(unsigned char *hdr)
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

	error = full_read(buf, len);
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
print_rapport_aspa(unsigned char *hdr)
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

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	printf("ASPA\t%u:[", assemble_u32(buf));
	for (p = 0; p < len; p += 4) {
		error = full_read(buf, sizeof(buf));
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
skip_pdu(unsigned char *hdr)
{
	uint32_t len;
	unsigned char buf[128];
	size_t n;
	int error;

	len = assemble_u32(&hdr[4]);
	if (len < 8) {
		pr_err("PDU length too small: %u", len);
		return EINVAL;
	}

	for (len -= 8; len != 0; len -= n) {
		n = len < sizeof(buf) ? len : sizeof(buf);
		error = full_read(buf, n);
		if (error)
			return error;
	}

	return 0;
}

static int
print_pdu(unsigned char *hdr)
{
	int error = EINVAL;

	/* Pre-print */
	switch (hdr[1]) {
	case 0:
	case 1:
	case 3:
	case 7:
		atomic_store(&session, assemble_u16(&hdr[2]));
	}

	switch (format) {
	case OF_PDU:
		switch (hdr[1]) {
		case 0:  error = print_pdu_serial_notify(hdr);	break;
		case 1:  error = print_pdu_serial_query(hdr);	break;
		case 2:  error = print_pdu_reset_query(hdr);	break;
		case 3:  error = print_pdu_cache_response(hdr);	break;
		case 4:  error = print_pdu_ipv4_prefix(hdr);	break;
		case 6:  error = print_pdu_ipv6_prefix(hdr);	break;
		case 8:  error = print_pdu_cache_reset(hdr);	break;
		case 7:  error = print_pdu_end_of_data(hdr);	break;
		case 9:  error = print_pdu_router_key(hdr);	break;
		case 10: error = print_pdu_error_report(hdr);	break;
		case 11: error = print_pdu_aspa_pdu(hdr);	break;
		default: error = print_pdu_unknown(hdr);	break;
		}
		break;

	case OF_RAPPORT:
		switch (hdr[1]) {
		case 4:  error = print_rapport_vrp4(hdr);	break;
		case 6:  error = print_rapport_vrp6(hdr);	break;
		case 10: error = print_rapport_errpdu(hdr);	break;
		case 11: error = print_rapport_aspa(hdr);	break;
		case 9:  /* Format still undecided */
		default: return skip_pdu(hdr);
		}
	}

	if (!error)
		printf("\n");
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
	unsigned char hdr[8];

	do {
		if (full_read(hdr, sizeof(hdr)) != 0)
			return;
		pr_trace("PDU received.");
		if (print_pdu(hdr) != 0)
			return;
	} while (!is_terminating_pdu(hdr[1]));
}

static void *
handle_server_pdus(void *arg)
{
	unsigned char hdr[8];

	do {
		if (full_read(hdr, sizeof(hdr)) != 0)
			return NULL;
		pr_trace("PDU received.");
		if (print_pdu(hdr) != 0)
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
	int error = 0;

	infile = stdin;

	register_signal_handlers();

	parse_options(argc, argv);

	if (strcmp(action, "reset") == 0) {
		connect_socket();
		__send_reset_query(version, 2, 0, 8);
		print_server_response();
		close_socket();

	} else if (strcmp(action, "serial") == 0) {
		connect_socket();
		__send_serial_query(version, 1, atomic_load(&session), 12, serial);
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
