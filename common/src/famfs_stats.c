/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>

#include "famfs_stats.h"
#include "famfs_error.h"


DEFINE_FAMSIM_STATS(famsim_stats_test, 0x000);
DEFINE_FAMSIM_STATS(famsim_stats_send, 0x001);
DEFINE_FAMSIM_STATS(famsim_stats_recv, 0x002);

#if (HAVE_FAM_SIM == 1)

void famsim_stats_init(struct famsim_stat_ctx **ctx_p,
    const char *dir, const char *fname, int id)
{
        struct famsim_stat_ctx *ctx;

	/* Turn off stats if we aren't on the simulator. */
	if (!ctx_p || !dir || !fname)
		return;
	if (!sim_api_is_sim()) {
                err("Not on simulator, stats disabled");
		return;
        }

        ctx = (struct famsim_stat_ctx *) calloc(1, sizeof(*ctx));
        ctx->stats_id = id;
        ctx->stats_dir = strdup(dir);
        ctx->stats_unique = strdup(fname);
        *ctx_p = ctx;

	famsim_stats_start(ctx, &famsim_stats_test);
	famsim_stats_stop(&famsim_stats_test, true);
	famsim_stats_start(ctx, &famsim_stats_test);
	famsim_stats_stop(&famsim_stats_test, true);
	famsim_stats_start(ctx, &famsim_stats_test);
	famsim_stats_pause(&famsim_stats_test);
	famsim_stats_start(ctx, &famsim_stats_test);
	famsim_stats_stop(&famsim_stats_test, true);
}

void famsim_stats_start(struct famsim_stat_ctx *ctx, struct famsim_stats *stats)
{
	char			*fname = NULL;
	int			save_errno;

	if (!ctx || stats->state == FAMSIM_STATS_RUNNING)
		return;
	if (!stats->buf) {
		if (sim_api_data_rec(DATA_REC_CREAT, stats->uid,
				     (uintptr_t)&stats->buf_len)) {
			err("uid %d:DATA_REC_CREAT failed", stats->uid);
			return;
		}
                stats->stat_ctx = ctx;

		if (asprintf(&fname, "%s/%s_%d.%d",
			     ctx->stats_dir, ctx->stats_unique,
			     ctx->stats_id,
			     stats->uid) == -1)
			goto init_error;
		stats->fd = open(fname, O_RDWR | O_CREAT | O_TRUNC,
				 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (stats->fd == -1) {
			save_errno = errno;
			err("uid %d:failed to open %s", stats->uid, fname);
			errno = save_errno;
			goto init_error;
		}
		free(fname);
		stats->buf = calloc(1, stats->buf_len);
		if (!stats->buf)
			goto init_error;
	}
	if (sim_api_data_rec(DATA_REC_START, stats->uid,
			     (uintptr_t)stats->buf)) {
		err("uid %d:DATA_REC_START failed", stats->uid);
		return;
	}
	stats->state = FAMSIM_STATS_RUNNING;
	return;

 init_error:
	free(fname);
	err("uid %d:initialization failed, error %d:%s",
	    stats->uid, errno, strerror(errno));
	famsim_stats_close(stats);
}

void famsim_stats_stop(struct famsim_stats *stats, int do_write)
{
	ssize_t			res;

	if (stats->state == FAMSIM_STATS_STOPPED)
		return;
	if (sim_api_data_rec(DATA_REC_STOP, stats->uid,
			     (uintptr_t)stats->buf)) {
		err("uid 0x%03x:DATA_REC_STOP failed",
		    stats->uid);
		return;
	}
	stats->state = FAMSIM_STATS_STOPPED;
	if (!do_write)
		return;
	res = write(stats->fd, stats->buf, stats->buf_len);
	if (res < 0) {
		err("uid 0x%03x:write() failed, error %d:%s",
		    stats->uid, errno, strerror(errno));
		return;
	}
	if ((size_t)res != stats->buf_len) {
		err("uid 0x%03x: wrote %ld/%ld bytes",
		    stats->uid, res, stats->buf_len);
		return;
	}
}

void famsim_stats_pause(struct famsim_stats *stats)
{
	if (stats->state != FAMSIM_STATS_RUNNING)
		return;
	if (sim_api_data_rec(DATA_REC_PAUSE, stats->uid,
			     (uintptr_t)stats->buf)) {
		err("uid 0x%03x:DATA_REC_PAUSE failed", stats->uid);
		return;
	}
	stats->state = FAMSIM_STATS_PAUSED;
}

void famsim_stats_close(struct famsim_stats *stats)
{
	struct famsim_stat_ctx *ctx = stats->stat_ctx;

	if (!ctx)
		return;

        if (stats->buf) {
		if (sim_api_data_rec(DATA_REC_END, stats->uid, (uintptr_t)stats->buf))
			err("uid 0x%03x:DATA_REC_END failed", stats->uid);
		if (stats->fd != -1)
			close(stats->fd);
		stats->fd = -1;
	}
	free(stats->buf);
	stats->buf = NULL;
	free(ctx->stats_dir);
	free(ctx->stats_unique);
	free(ctx);
}

#endif /* HAVE_FAM_SIM == 1 */
