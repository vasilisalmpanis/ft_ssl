#include <ft_ssl.h>

struct blake2_data {
};

static void blake2_init(struct program_ctx *ctx)
{
	struct blake2_data *data = malloc(sizeof(struct blake2_data));
	if (data == NULL) error("Fatal: Out of memory");

	memset(data, 0, sizeof(struct blake2_data));
	ctx->data = data;
}

static void blake2_digest(struct program_ctx *ctx, bool stdin)
{
	(void)ctx;
	(void)stdin;
}

static void blake2_free(struct program_ctx *ctx)
{
	(void)ctx;
}

struct hash_type blake2_type = {
	.name 		= "blake2",
	.id 		= BLAKE2,
	.digest_size 	= 0,
	.init 		= blake2_init,
	.digest 	= blake2_digest,
	.free 		= blake2_free
};
