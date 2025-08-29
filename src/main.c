#include <ft_ssl.h>

static struct hash_type *type_table[] = {
	&md5_type,
	&sha256_type,
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

char *read_file_to_buffer(int fd, size_t *out_size)
{
    size_t capacity = 1024;   // initial buffer size
    size_t size = 0;
    char *buffer = malloc(capacity);
    if (!buffer)
        return NULL;

    ssize_t bytes;
    while ((bytes = read(fd, buffer + size, capacity - size)) > 0) {
        size += bytes;
        if (size == capacity) {
            capacity *= 2;
            char *new_buf = realloc(buffer, capacity);
            if (!new_buf) {
                free(buffer);
                return NULL;
            }
            buffer = new_buf;
        }
    }

    if (bytes < 0) { // read error
        free(buffer);
        return NULL;
    }

    // Optional: add null terminator if you want to treat it as string
    buffer[size] = '\0';

    if (out_size)
        *out_size = size;

    return buffer;
}

void hash(struct program_ctx* ctx, bool stdin)
{
	if (ctx->user_input == NULL) error("Please provide content to be hashed\n");
	if (ctx->type.init) {
		ctx->type.init(ctx);
	}
	if (ctx->type.digest) {
		ctx->type.digest(ctx, stdin);
	}
	if (ctx->type.free) {
		ctx->type.free(ctx);
	}
}

void parse_args(struct program_ctx *ctx, int argc, char **argv)
{
	char *file = NULL;
	char *string = NULL;
	char *stdin = NULL;
	size_t out_size;
	parse_type(ctx, argv[1]);
	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0) {
			ctx->echo = true;
			stdin = read_file_to_buffer(STDIN_FILENO, &out_size);
			if (stdin == NULL) return ;

			ctx->user_input = (uint8_t *)stdin;
			ctx->user_input_len = out_size;
			hash(ctx, true);
			free(stdin);
			continue;
		}
		else if (strcmp(argv[i], "-q") == 0) {
			ctx->quiet = true;
			continue;
		}
		else if (strcmp(argv[i], "-r") == 0) {
			ctx->reverse = true;
			continue;
		}
		else if (!file && strcmp(argv[i], "-s") == 0) {
			if (i + 1 < argc) {
				string = argv[i + 1];
				ctx->user_input = (uint8_t *)string;
				ctx->user_input_len = strlen(string);
				hash(ctx, false);
				i++;
			} else {
				printf("%s: %s: Invalid argument\n", argv[0], argv[i]);
			}
		} else {
			int fd = open(argv[i], O_RDONLY);
			if (fd < 0) {
				printf("%s: %s: %s: No such file or directory\n", argv[0], ctx->type.name, argv[i]);
				continue;
			}
			file = read_file_to_buffer(fd, &out_size);
			if (!file) {
				close(fd);
				continue;
			}
			ctx->user_input = (uint8_t *)file;
			ctx->user_input_len = out_size;
			hash(ctx, false);
			free(file);
			file = NULL;
		}
	}
	if (ctx->user_input == NULL) {
		stdin = read_file_to_buffer(STDIN_FILENO, &out_size);
		if (stdin == NULL) return ;

		ctx->user_input = (uint8_t *)stdin;
		ctx->user_input_len = out_size;
		hash(ctx, false);
		free(stdin);
	}
}

int main(int argc, char *argv[])
{
	char *program_name = argv[0];
	struct program_ctx context;
	context.fd = STDIN_FILENO;

	if (argc == 1) {
		usage(program_name);
		exit(0);
	}
	memset(&context, 0, sizeof(struct program_ctx));
	parse_args(&context, argc, argv);
	return 0;
}
