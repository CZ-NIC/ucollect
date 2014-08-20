#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define LINE_BUFF 1024
#define STR_BUFF 128

struct rule {
	struct in6_addr addr;
	size_t prefix;
	int family;
};

void usage(const char *prgname) {
	fprintf(stderr, "Usage: %s address prefix [address prefix] [...]\n", prgname);
}

bool bitcmp(unsigned char *a, unsigned char *b, size_t bits) {

	do {
		if (a[0] != b[0]) return false;
		a++;
		b++;
		bits -= 8;
	} while (bits >= 8);

	unsigned char bitmask = (0xFF << (8-bits));
	if ((a[0] & bitmask) != (b[0] & bitmask)) return false;

	return true;
}

bool parse_address(const char *addrstr, struct in6_addr *addr, int *family) {
	if (inet_pton(AF_INET, addrstr, addr)) {
		*family = 4;
		return true;
	}
	if (inet_pton(AF_INET6, addrstr, addr)) {
		*family = 6;
		return true;
	}

	return false;
}

int main(int argc, char **argv) {
	if (argc < 3 || (argc % 2) != 1) {
		usage(argv[0]);
		return 1;
	}

	size_t rules_cnt = (argc - 1) / 2;
	struct rule rules[rules_cnt];

	for (size_t i = 0 ; i < rules_cnt; i++) {
		if (!parse_address(argv[2*i+1], &(rules[i].addr), &(rules[i].family))) {
			fprintf(stderr, "Parsing of address %s failed\n", argv[2*i+1]);
			return 2;
		}
		rules[i].prefix = atoi(argv[2*i+2]);
		if (rules[i].prefix <= 0 && rules[i].prefix > ((rules[i].family == 4) ? 32 : 128)) {
			fprintf(stderr, "Parsing of IPv4 subnet prefix failed\n");
			return 2;
		}
	}

	char line[LINE_BUFF];
	char dummy[STR_BUFF];
	char addrstr[STR_BUFF];
	struct in6_addr addr;
	int family;

	while (fgets(line, LINE_BUFF, stdin)) {
		bool print = true;
		sscanf(line, "%[^','],%[^','],%[^',']", dummy, dummy, addrstr);
		if (parse_address(addrstr, &addr, &family)) {
			for (size_t i = 0; i < rules_cnt; i++) {
				if (
					family == rules[i].family &&
					bitcmp((unsigned char *) &addr, (unsigned char *) &(rules[i].addr), rules[i].prefix)
				) {
					print = false;
				}
			}
		}
		if (print) {
			fprintf(stdout, "%s", line);
		}
	}

	return 0;
}
