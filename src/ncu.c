#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Similar to nc -uU <argv[1]>, except it closes the connection and quits
 * right after receiving end of standard input.
 * Does not expect a server response.
 */
int
main(int argc, char **argv)
{
	int fd;
	size_t inputlen, maxlen;
	struct sockaddr_un addr;
	size_t addrlen;
	char buf[256];
	size_t consumed;

	if (argc < 2) {
		printf("Usage: echo \"<command>\" | barry-ncu <input-src>\n");
		printf("Sends a command to interactive barry-rtr.\n");
		return EXIT_FAILURE;
	}

	inputlen = strlen(argv[1]);
	maxlen = sizeof(addr.sun_path) - 1;
	if (inputlen > maxlen) {
		fprintf(stderr, "<input-src> is too long: %zu > %zu\n",
		    inputlen, maxlen);
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, argv[1]);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	addrlen = sizeof(struct sockaddr_un);
	if (connect(fd, (const struct sockaddr *)&addr, addrlen) < 0) {
		fprintf(stderr, "Server unreachable: %s\n", strerror(errno));
		close(fd);
		return EXIT_FAILURE;
	}

	while (1) {
		consumed = fread(buf, 1, sizeof(buf), stdin);
		if (consumed != 0) {
			if (write(fd, buf, consumed) < 0) {
				fprintf(stderr, "Write failed: %s\n",
				    strerror(errno));
				close(fd);
				return EXIT_FAILURE;
			}

		}
		if (consumed < sizeof(buf)) {
			if (feof(stdin))
				break;
			if (ferror(stdin)) {
				fprintf(stderr, "Read failed: Unknown error\n");
				close(fd);
				return EXIT_FAILURE;
			}
		}
	}

	close(fd);
	return EXIT_SUCCESS;
}
