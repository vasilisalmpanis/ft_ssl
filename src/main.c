#include <ft_ssl.h>

static struct table type_table[] = {
	{"md5", MD5, 16},
	{"sha256", SHA256, 0},
	{0},
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
	for (int i = 0; type_table[i].type != 0; i++) {
		if (memcmp(type, type_table[i].name, strlen(type)) == 0) {
			// Initialize context
			ctx->type = type_table[i].type;
			ctx->digest_size = type_table[i].digest_size;
			ctx->digest = (uint8_t *)malloc(type_table[i].digest_size);
			if (ctx->digest == NULL) error("Fatal: Out of memory");
		}
	}
	if (ctx->type == NONE) error(INVALID_TYPE, type);
}

void parse_args(struct program_ctx *ctx, int argc, char **argv)
{
	parse_type(ctx, argv[1]);
	for (int i = 2; i < argc; i++) {
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
	printf("Success we are parsing correctly\n");
	return 0;
}
