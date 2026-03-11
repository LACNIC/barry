#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "print.h"

static char *action;
static char *server;
static char *port = "323";
static uint8_t version = 2;
static atomic_uint session;
static uint32_t serial;

unsigned int verbosity;
bool print_colors;

static char const *cmd = "";
static char const *flg = "";
static char const *var = "";
static char const *enm = "";
static char const *man = "";
static char const *ref = "";
static char const *rst = "";

static int fd;
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
	printf("  barry-rtr [%s-h%s][%s-v%s[%sv%s]][%s-c%s] \\\n", flg, rst, flg, rst, flg, rst, flg, rst);
	printf("      [%s-V%s<version>%s][%s-s%s<session>%s][%s-l%s<serial>%s] \\\n", flg, var, rst, flg, var, rst, flg, var, rst);
	printf("      %s<action>%s %s<server>%s [%s<port>%s]\n", var, rst, var, rst, var, rst);
	printf("\n");
	printf("%s<action>%s is either '%sreset%s', '%sserial%s' or '%sinteractive%s'.\n", var, rst, enm, rst, enm, rst, enm, rst);
	printf("  - '%sreset%s' connects, sends one Reset Query PDU, prints all received PDUs,\n", enm, rst);
	printf("    and exits once a %sterminating PDU%s is received.\n", ref, rst);
	printf("  - '%sserial%s' connects, sends one Serial Query PDU, prints all received PDUs,\n", enm, rst);
	printf("    and exits once a %sterminating PDU%s is received.\n", ref, rst);
	printf("  - '%sinteractive%s' connects, then expects commands from standard input.\n", enm, rst);
	printf("    Run 'help' during interactive mode for more information.\n");
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
	printf("  %s-V%s sets RTR version number (Default: %u)\n", flg, rst, version);
	printf("  %s-s%s sets the session ID (Default: %u)\n", flg, rst, atomic_load(&session));
	printf("     (Effective in '%sserial%s' and '%sinteractive%s' modes only)\n", enm, rst, enm, rst);
	printf("  %s-l%s sets the request's serial\n", flg, rst);
	printf("     (Effective in '%sserial%s' mode only)\n", enm, rst);
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
		{ "version", required_argument, 0, 'V' },
		{ "session", required_argument, 0, 's' },
		{ "serial",  required_argument, 0, 'l' },
		{ 0 }
	};
	int opt;
	bool help = false;

	atomic_init(&session, 0);

	while ((opt = getopt_long(argc, argv, "hvcV:s:l:", opts, NULL)) != -1) {
		switch (opt) {
		case 'h':	help = true;		break;
		case 'v':	verbosity++;		break;
		case 'c':	enable_colors();	break;
		case 'V':	parse_getopt_version();	break;
		case 's':	parse_getopt_session();	break;
		case 'l':	parse_getopt_serial();	break;
		case '?':	print_help();		exit(EXIT_FAILURE);
		}
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
	pr_debug("   --version (-V) = %u", version);
	pr_debug("   --session (-s) = %u", session);
	pr_debug("   --serial  (-l) = %u", serial);
	pr_debug("");
}

static void
connect_socket(void)
{
	struct addrinfo hints = { 0 };
	struct addrinfo *alternatives, *alt;
	int error;

	pr_trace("Connecting to server...");

	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	error = getaddrinfo(server, port, &hints, &alternatives);
	if (error) {
		panic("getaddrinfo: %s", gai_strerror(error));
		exit(EXIT_FAILURE);
	}

	for (alt = alternatives; alt != NULL; alt = alt->ai_next) {
		fd = socket(alt->ai_family, alt->ai_socktype, alt->ai_protocol);
		if (fd < 0) {
			panic("socket(%s, %s): %s\n", server, port,
			    strerror(errno));
			continue;
		}
		if (connect(fd, alt->ai_addr, alt->ai_addrlen) != -1)
			break; /* Success */

		panic("connect(%s, %s): %s\n", server, port, strerror(errno));
		close(fd);
	}

	freeaddrinfo(alternatives);

	if (!alt)
		panic("None of the addrinfo candidates could connect.\n");
	pr_trace("Done.");
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
		written = write(fd, msg, len);
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
send_stdin_commands(void)
{
	struct line_reader rdr = { 0 };
	char *token;
	int error;

	while (getline(&rdr.line, &rdr.lsize, stdin) != -1) {
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

	pr_trace("Cancelling socket thread.");
	error = pthread_cancel(socket_thread);
	if (error)
		pr_err("Cound not cancel socket thread: %s. "
		    "IDK; try interrupting the process.",
		    strerror(error));

	if (feof(stdin)) {
		pr_trace("End of standard input reached.");
		return 0;
	}
	if (ferror(stdin)) {
		pr_err("Looks like there was some error reading stdin.");
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
		consumed = read(fd, buf, size);
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

static int
print_addr4(char const *pfx, size_t *remainder)
{
	unsigned char buf[4];
	struct in_addr addr;
	char addr_strbuf[INET_ADDRSTRLEN];
	char const *addr_str;
	int error;

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	addr.s_addr = htonl(assemble_u32(buf));
	addr_str = inet_ntop(AF_INET, &addr, addr_strbuf, sizeof(addr_strbuf));
	if (!addr_str)
		pr_warn("Cannot convert addr4 to string: %s", strerror(errno));
	printf("%s %s ", pfx, addr_str ? addr_str : "null");

	*remainder -= 4;
	return 0;
}

static int
print_addr6(char const *pfx, size_t *remainder)
{
	unsigned char buf[16];
	struct in6_addr addr;
	char addr_strbuf[INET6_ADDRSTRLEN];
	char const *addr_str;
	int error;

	error = full_read(buf, sizeof(buf));
	if (error)
		return error;

	addr.s6_addr32[0] = htonl(assemble_u32(buf));
	addr.s6_addr32[1] = htonl(assemble_u32(&buf[4]));
	addr.s6_addr32[2] = htonl(assemble_u32(&buf[8]));
	addr.s6_addr32[3] = htonl(assemble_u32(&buf[12]));
	addr_str = inet_ntop(AF_INET6, &addr, addr_strbuf, sizeof(addr_strbuf));
	if (!addr_str)
		pr_warn("Cannot convert addr6 to string: %s", strerror(errno));
	printf("%s %s ", pfx, addr_str ? addr_str : "null");

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
			consumed = read(fd, buf, 1024 < len ? 1024 : len);
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

	if (strcmp("session", field3_what) == 0)
		atomic_store(&session, field3);

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
		consumed = read(fd, buf, len < sizeof(buf) ? len : sizeof(buf));
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
print_serial_notify(unsigned char *hdr)
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
print_serial_query(unsigned char *hdr)
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
print_reset_query(unsigned char *hdr)
{
	printf("reset-query    ");
	return print_remainder(print_hdr1(hdr, "zero"));
}

static int
print_cache_response(unsigned char *hdr)
{
	printf("cache-response ");
	return print_remainder(print_hdr1(hdr, "session"));
}

static int
print_ipv4_prefix(unsigned char *hdr)
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
print_ipv6_prefix(unsigned char *hdr)
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
print_end_of_data(unsigned char *hdr)
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
print_cache_reset(unsigned char *hdr)
{
	printf("cache-reset    ");
	return print_remainder(print_hdr1(hdr, "zero"));
}

static int
print_router_key(unsigned char *hdr)
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
print_aspa_pdu(unsigned char *hdr)
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
print_error_report(unsigned char *hdr)
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
print_unknown(unsigned char *hdr)
{
	printf("unknown        ");
	return print_remainder(print_hdr1(hdr, "?"));
}

static int
print_pdu(unsigned char *hdr)
{
	switch (hdr[1]) {
	case 0:  return print_serial_notify(hdr);
	case 1:  return print_serial_query(hdr);
	case 2:  return print_reset_query(hdr);
	case 3:  return print_cache_response(hdr);
	case 4:  return print_ipv4_prefix(hdr);
	case 6:  return print_ipv6_prefix(hdr);
	case 8:  return print_cache_reset(hdr);
	case 7:  return print_end_of_data(hdr);
	case 9:  return print_router_key(hdr);
	case 10: return print_error_report(hdr);
	case 11: return print_aspa_pdu(hdr);
	default: return print_unknown(hdr);
	}
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
		printf("\n");
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
		printf("\n");
	} while (true);
}

static void
start_socket_listener(void)
{
	int error;

	pr_trace("Starting socket thread.");
	error = pthread_create(&socket_thread, NULL, handle_server_pdus, NULL);
	if (error)
		panic("pthread_create(): %s", strerror(error));
}

static void
stop_socket_listener(void)
{
	int error;

	pr_trace("Joining socket thread.");;
	error = pthread_join(socket_thread, NULL);
	if (error)
		pr_err("pthread_join(): %s", strerror(error));

	pr_trace("Closing socket.");
	close(fd);
}

int
main(int argc, char **argv)
{
	int error = 0;

	register_signal_handlers();

	parse_options(argc, argv);

	if (strcmp(action, "reset") == 0) {
		connect_socket();
		__send_reset_query(version, 2, 0, 8);
		print_server_response();
		close(fd);

	} else if (strcmp(action, "serial") == 0) {
		connect_socket();
		__send_serial_query(version, 1, atomic_load(&session), 12, serial);
		print_server_response();
		close(fd);

	} else if (strcmp(action, "interactive") == 0) {
		connect_socket();
		start_socket_listener();
		error = send_stdin_commands();
		stop_socket_listener();

	} else {
		pr_err("Unknown action: %s", action);
		error = EINVAL;
	}

	return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
