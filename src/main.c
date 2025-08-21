#include <ft_ssl.h>
#include <stdio.h>
#include <string.h>

static struct hash_type *type_table[] = {
	&md5_type,
	NULL,
};

void help()
{
	printf("%s", HELP_MSG);
}

void usage(char *name)
{
	printf("Usage: %s %s", name, USAGE_MSG);
	help();
}

void parse_type(struct program_ctx *ctx, char *type)
{
	for (int i = 0; type_table[i] != NULL; i++) {
		if (memcmp(type, type_table[i]->name, strlen(type)) == 0) {
			// Initialize context
			ctx->type = *type_table[i];
		}
	}
	if (ctx->type.id == NONE) error(INVALID_TYPE, type);
}

void parse_args(struct program_ctx *ctx, int argc, char **argv)
{
	parse_type(ctx, argv[1]);
	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0)
			ctx->echo = true;
		else if (strcmp(argv[i], "-s") == 0)
			ctx->quiet = true;
		else if (strcmp(argv[i], "-q") == 0)
			ctx->reverse = true;
		else if (strcmp(argv[i], "-r") == 0)
			ctx->print_sum = true;

	}
}

/*
 * MD% steps
 * 1. Input Padding
 * 2. Length Appending
 * 3. Buffer Initialization
 * 4. Message Processing
 * 5. Output
 */
int main(int argc, char *argv[])
{
	char *program_name = argv[0];
	struct program_ctx context;

	if (argc == 1) {
		usage(program_name);
		exit(0);
	}
	memset(&context, 0, sizeof(struct program_ctx));
	parse_args(&context, argc, argv);
	if (context.type.init) {
		context.type.init(&context);
	}
	if (context.type.update) {
		context.type.update(&context);
	}
	if (context.type.finalize) {
		context.type.finalize(&context);
	}
	printf("digest: %s\n", context.digest);
	if (context.type.free) {
		context.type.free(&context);
	}
	return 0;
}
