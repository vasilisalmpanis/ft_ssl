#include <ft_ssl.h>
#include <stdio.h>
#include <string.h>


static void md5_init(struct program_ctx *ctx);
static void md5_update(struct program_ctx *ctx);
static void md5_step(struct program_ctx *ctx);
static void md5_finalize(struct program_ctx *ctx);
static void md5_free(struct program_ctx *ctx);

struct hash_type md5_type = {"md5", MD5, 16, md5_init, md5_update, md5_step, md5_finalize, md5_free};

static void md5_init(struct program_ctx *ctx)
{
	ctx->digest = (uint8_t *)malloc(md5_type.digest_size);
	if (ctx->digest == NULL) error("Fatal: Out of memory");
	memset(ctx->digest, 0, md5_type.digest_size);
	memcpy(ctx->digest, "hello", md5_type.digest_size);
}

static void md5_update(struct program_ctx *ctx)
{
	(void)ctx;
}

static void md5_step(struct program_ctx *ctx)
{
	(void)ctx;
}

static void md5_finalize(struct program_ctx *ctx)
{
	(void)ctx;
}

static void md5_free(struct program_ctx *ctx)
{
	if (ctx->digest)
		free(ctx->digest);
}
