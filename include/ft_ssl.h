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
	"md5 sha256 blake2s256\n" \
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
#define BLAKE2 3

extern struct hash_type md5_type;
extern struct hash_type sha256_type;
extern struct hash_type blake2_type;

struct program_ctx;

struct hash_type {
	void (*init)(struct program_ctx *);
	void (*digest)(struct program_ctx *, bool stdin);
	void (*free)(struct program_ctx *);

	size_t digest_size;
	char *name;
	int id;

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
static void print_hex_digest(struct program_ctx *ctx, uint8_t *digest)
{
	for (size_t i = 0; i < ctx->type.digest_size; i++) {
		printf("%02x", digest[i]);
	}
}

__attribute__((unused))
static void print_input(uint8_t *input, size_t len, bool trim_newline)
{
	if (trim_newline && len > 0 && input[len - 1] == '\n') {
		len--;
	}
	for (size_t i = 0; i < len; i++) {
		printf("%c", input[i]);
	}
}

__attribute__((unused))
static void print_digest(struct program_ctx* ctx, char* type, uint8_t *digest, bool stdin)
{
	if (ctx->quiet) {
		if (stdin && ctx->echo)
			print_input(ctx->user_input, ctx->user_input_len, false);
		print_hex_digest(ctx, digest);
		printf("\n");
		return ;
	}
	if (stdin && ctx->echo) {
		printf("(\"");
		print_input(ctx->user_input, ctx->user_input_len, true);
		printf("\")= ");
		print_hex_digest(ctx, digest);
		printf("\n");
		return ;
	}
	if (ctx->reverse) {
		print_hex_digest(ctx, digest);
		if (stdin)
			printf(" (stdin)");
		else if (ctx->file)
			printf(" %s", ctx->filename);
		else
			printf(" \"%s\"", ctx->user_input);
		printf("\n");
		return ;
	}
	if (stdin)
		printf("(stdin)= ");
	else if (ctx->file)
		printf("%s (%s) = ", type, ctx->filename);
	else
		printf("%s (\"%s\") = ", type, ctx->user_input);
	print_hex_digest(ctx, digest);
	printf("\n");
}
