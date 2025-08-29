#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>

#define USAGE_MSG "command [flags]... [file/string]...\n"
#define INVALID_TYPE "Invalid command '%s'; type \"help\" for a list.\n"
#define HELP_MSG  "\nStandard commands:\n" \
	"md5 sha256\n" \
	"\nOptions:\n" \
	"  -p	echo STDIN to STDOUT and append the checksum to STDOUT\n" \
	"  -q	quiet mode\n" \
	"  -r	reverse the format of the output\n" \
	"  -s	print the sum of the given string\n" \
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
	void (*digest)(struct program_ctx *, bool stdin);
	void (*free)(struct program_ctx *);
};

struct program_ctx {
	bool quiet;
	bool reverse;
	bool print_sum;
	bool echo;

	bool file;
	char *filename;

	int fd;

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

__attribute__((unused))
static void print_digest(struct program_ctx* ctx, char* type, uint8_t *digest, bool stdin)
{
	if (ctx->reverse) {
		for(int i = 0; i < ctx->type.digest_size; i++) {
			printf("%02x", digest[i]);
		}
		if (stdin && !ctx->quiet) {
			if (ctx->echo)
				printf(" (\"%s\") ", ctx->user_input);
			else
				printf(" (stdin) ");
		}
		else if (ctx->user_input) {
			if (!ctx->quiet && ctx->file) {
				printf(" %s ", ctx->filename);
			} else if (!ctx->quiet) {
				printf(" \"%s\" ", ctx->user_input);
			}
		}
	} else {
		if (stdin && !ctx->quiet) {
			if (ctx->echo)
				printf("(\"%s\")= ", ctx->user_input);
			else
				printf("(stdin)= ");
		}
		else if (ctx->user_input) {
			if (!ctx->quiet && ctx->file) {
				printf("%s(%s)= ", type, ctx->filename);
			} else if (!ctx->quiet) {
				printf("%s(\"%s\")= ", type, ctx->user_input);
			}
		}
		for(int i = 0; i < ctx->type.digest_size; i++) {
			printf("%02x", digest[i]);
		}
	}
	printf("\n");
}
