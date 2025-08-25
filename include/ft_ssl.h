#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#define USAGE_MSG "command [flags]... [file/string]...\n"
#define INVALID_TYPE "Invalid command '%s'; type \"help\" for a list.\n"
#define HELP_MSG  "\nStandard commands:\n" \
	"md5 sha256\n" \
	"\nOptions:\n" \
	"  -p	echo STDIN to STDOUT and append the checksum to STDOUT\n" \
	"  -s	quiet mode\n" \
	"  -q	reverse the format of the output\n" \
	"  -r	print the sum of the given string\n" \
	"\nExit status:\n" \
	" 0  if OK,\n" \
	" 1  if minor problems\n" \
	" 2  if serious trouble (e.g., cannot access command-line argument).\n"

#define NONE 0
#define MD5 1
#define SHA256 2

extern struct hash_type md5_type;
extern struct hash_type sha256_type;

struct program_ctx;

struct hash_type {
	char* name;
	int id;
	int digest_size;

	void (*init)(struct program_ctx *);
	void (*digest)(struct program_ctx *);
	void (*free)(struct program_ctx *);
};

struct program_ctx {
	bool quiet;
	bool reverse;
	bool print_sum;
	bool echo;

	uint8_t *user_input;
	size_t user_input_len;

	struct hash_type type;
	void *data;
};

#define error(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        exit(1); \
    } while (0)
