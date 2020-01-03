/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 * Copyright (c) 2018 - Michael J. Brim
 * Copyright (c) 2017-2018, HPE - Oleg Neverovitch, Dmitry Ivanov
 */

#ifdef __cplusplus
# include <cassert>
# include <cctype>
# include <cerrno>
# include <cstddef>
# include <cstdlib>
# include <cstring>
#else
# include <assert.h>
# include <ctype.h>
# include <errno.h>
# include <stddef.h>
# include <stdlib.h>
# include <string.h>
#endif

#include <getopt.h>   // getopt_long()
#include <sys/stat.h> // stat()
#include <unistd.h>

#include "ini.h"
#include "tinyexpr.h"
#include "famfs_configurator.h"

#define UNIFYCR_CFG_MAX_MSG 1024

#define stringify_indirect(x) #x
#define stringify(x) stringify_indirect(x)


// initialize configuration using all available methods
int unifycr_config_init(unifycr_cfg_t *cfg,
                        int argc,
                        char **argv)
{
    int rc;
    char *syscfg = NULL;

    if (cfg == NULL)
        return -1;

    memset((void *)cfg, 0, sizeof(unifycr_cfg_t));

    // set default configuration
    rc = unifycr_config_set_defaults(cfg);
    if (rc)
        return rc;

    // validate default settings
    rc = unifycr_config_validate(cfg);
    if (rc)
        return rc;

    // process system config file (if available)
    syscfg = cfg->unifycr_configfile;
    rc = configurator_file_check(NULL, NULL, syscfg, NULL);
    if (rc == 0) {
        rc = unifycr_config_process_ini_file(cfg, syscfg);
        if (rc)
            return rc;
    }
    if (syscfg != NULL)
        free(syscfg);
    cfg->unifycr_configfile = NULL;

    // process environment (overrides defaults and system config)
    rc = unifycr_config_process_environ(cfg);
    if (rc)
        return rc;

    // process command-line args (overrides all previous)
    rc = unifycr_config_process_cli_args(cfg, argc, argv);
    if (rc)
        return rc;

    // read config file passed on command-line (does not override cli args)
    if (cfg->unifycr_configfile != NULL) {
        rc = unifycr_config_process_ini_file(cfg, cfg->unifycr_configfile);
        if (rc)
            return rc;
    }

    // validate settings
    rc = unifycr_config_validate(cfg);
    if (rc)
        return rc;

    // check and set multi-section ids
    rc = famfs_config_check_multisec(cfg);
    return rc;
}

// cleanup allocated state
void unifycr_config_free(unifycr_cfg_t *cfg)
{
    if (cfg == NULL)
        return;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)       \
    if (cfg->sec##_##key != NULL) {                     \
        free(cfg->sec##_##key);                         \
        cfg->sec##_##key = NULL;                        \
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    if (cfg->sec##_##key != NULL) {                             \
        free(cfg->sec##_##key);                                 \
        cfg->sec##_##key = NULL;                                \
    }

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)	\
    for (unsigned uu=0; uu < F_CFG_MSEC_MAX; uu++) {		\
	for (unsigned u=0; u < (me>0?me:F_CFG_MSKEY_MAX); u++) {\
	    if (cfg->sec##_##key[uu][u] != NULL) {		\
		free(cfg->sec##_##key[uu][u]);			\
		cfg->sec##_##key[uu][u] = NULL;			\
	    }							\
	}							\
    }								\
    cfg->n_##sec##_##key = 0;

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    for (u = 0; u < me; u++) {                                          \
        if (cfg->sec##_##key[u] != NULL) {                              \
            free(cfg->sec##_##key[u]);                                  \
            cfg->sec##_##key[u] = NULL;                                 \
        }                                                               \
    }                                                                   \
    cfg->n_##sec##_##key = 0;

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
}

// print configuration to specified file (or stderr)
void unifycr_config_print(unifycr_cfg_t *cfg,
                          FILE *fp)
{
    char msg[UNIFYCR_CFG_MAX_MSG];

    if (fp == NULL)
        fp = stderr;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)                       \
    if (cfg->sec##_##key != NULL) {                                     \
        snprintf(msg, sizeof(msg), "FAMFS CONFIG: %s.%s = %s",        \
                 #sec, #key, cfg->sec##_##key);                         \
        fprintf(fp, "%s\n", msg);                                       \
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)         \
    if (cfg->sec##_##key != NULL) {                                     \
        snprintf(msg, sizeof(msg), "FAMFS CONFIG: %s.%s = %s",        \
                 #sec, #key, cfg->sec##_##key);                         \
        fprintf(fp, "%s\n", msg);                                       \
    }

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    for (unsigned uu=0; uu < F_CFG_MSEC_MAX; uu++) {			\
	for (unsigned u=0; u < (me>0?me:F_CFG_MSKEY_MAX); u++) {	\
	    if (cfg->sec##_##key[uu][u] != NULL) {			\
		if (me == 1)						\
		    snprintf(msg, sizeof(msg),				\
			    "FAMFS CONFIG: %s[%u].%s = %s",		\
			    #sec, uu, #key, cfg->sec##_##key[uu][u]);	\
		else							\
		    snprintf(msg, sizeof(msg),				\
			    "FAMFS CONFIG: %s[%u].%s[%u] = %s",		\
			    #sec, uu, #key, u, cfg->sec##_##key[uu][u]);\
		fprintf(fp, "%s\n", msg);				\
	    }								\
	}								\
    }

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    for (u = 0; u < me; u++) {                                          \
        if (cfg->sec##_##key[u] != NULL) {                              \
            snprintf(msg, sizeof(msg), "FAMFS CONFIG: %s.%s[%u] = %s", \
                     #sec, #key, u+1, cfg->sec##_##key[u]);             \
            fprintf(fp, "%s\n", msg);                                   \
        }                                                               \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    fflush(fp);
}

// print configuration in .ini format to specified file (or stderr)
void unifycr_config_print_ini(unifycr_cfg_t *cfg,
                              FILE *inifp)
{
    const char *curr_sec = NULL;
    const char *last_sec = NULL;

    if (inifp == NULL)
        inifp = stderr;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)                       \
    if (cfg->sec##_##key != NULL) {                                     \
        curr_sec = #sec;                                                \
        if ((last_sec == NULL) || (strcmp(curr_sec, last_sec) != 0))    \
            fprintf(inifp, "\n[%s]\n", curr_sec);                       \
        fprintf(inifp, "%s = %s\n", #key, cfg->sec##_##key);            \
        last_sec = curr_sec;                                            \
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)         \
    if (cfg->sec##_##key != NULL) {                                     \
        curr_sec = #sec;                                                \
        if ((last_sec == NULL) || (strcmp(curr_sec, last_sec) != 0))    \
            fprintf(inifp, "\n[%s]\n", curr_sec);                       \
        fprintf(inifp, "%s = %s\n", #key, cfg->sec##_##key);            \
        last_sec = curr_sec;                                            \
    }

/* FIXME */
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    for (unsigned u = 0; u < (me>0?me:F_CFG_MSKEY_MAX); u++) {		\
	if (cfg->sec##_##key[0][u] != NULL) {				\
	    curr_sec = #sec;						\
	    if ((last_sec == NULL) || (strcmp(curr_sec, last_sec) != 0)) \
		fprintf(inifp, "\n[%s]\n", curr_sec);			\
	    fprintf(inifp, "%s = %s ; (instance %u)\n",			\
		    #key, cfg->sec##_##key[0][u], u);			\
	    last_sec = curr_sec;					\
	}								\
    }

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    for (u = 0; u < me; u++) {                                          \
        if (cfg->sec##_##key[u] != NULL) {                              \
            curr_sec = #sec;                                            \
            if ((last_sec == NULL) || (strcmp(curr_sec, last_sec) != 0)) \
                fprintf(inifp, "\n[%s]\n", curr_sec);                   \
            fprintf(inifp, "%s = %s ; (instance %u)\n",                 \
                    #key, cfg->sec##_##key[u], u+1);                    \
            last_sec = curr_sec;                                        \
        }                                                               \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    fflush(inifp);
}

// set default values given in UNIFYCR_CONFIGS
int unifycr_config_set_defaults(unifycr_cfg_t *cfg)
{
    char *val;

    if (cfg == NULL)
        return -1;

    /* init keys */
#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)		\
    val = stringify(dv);					\
    if (0 != strcmp(val, "NULLSTRING")) {			\
      if (!strcmp(#typ, "STRING") && val[0] == '\"' && strlen(val) > 1)\
	cfg->sec##_##key = strndup(val+1, strlen(val)-2);	\
      else							\
        cfg->sec##_##key = strdup(val);				\
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    val = stringify(dv);                                        \
    if (0 != strcmp(val, "NULLSTRING"))                         \
        cfg->sec##_##key = strdup(val);

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    cfg->n_##sec##_##key = 0;						\
    val = stringify(dv);						\
    if (0 != strcmp(val, "NULLSTRING")) {				\
	for (unsigned u=0; u < F_CFG_MSEC_MAX; u++) {			\
	    cfg->sec##_##key[u][0] =					\
	     (!strcmp(#typ,"STRING") && val[0]=='\"' && strlen(val)>1)?	\
			strndup(val+1, strlen(val)-2) : strdup(val);	\
	}								\
    }

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    cfg->n_##sec##_##key = 0;                                           \
    memset((void *)cfg->sec##_##key, 0, sizeof(cfg->sec##_##key));

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    return 0;
}


// utility routine to print CLI usage (and optional usage error message)
void unifycr_config_cli_usage(char *arg0)
{
    fprintf(stderr, "USAGE: %s [options]\n", arg0);

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)         \
    fprintf(stderr, "    -%c,--%s-%s <%s>\t%s (default value: %s)\n",   \
            opt, #sec, #key, #typ, use, stringify(dv));

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    fprintf(stderr, "    -%c,--%s-%s <%s>\t%s (multiple values supported - max %u entries)\n", \
            opt, #sec, #key, #typ, use, me);

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    fflush(stderr);
}

// print usage error message
void unifycr_config_cli_usage_error(char *arg0,
                                    char *err_msg)
{
    if (err_msg != NULL)
        fprintf(stderr, "USAGE ERROR: %s : %s\n\n", arg0, err_msg);

    unifycr_config_cli_usage(arg0);
}


static struct option cli_options[] = {
#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)
#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    { #sec "-" #key, required_argument, NULL, opt },
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)
#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    { #sec "-" #key, required_argument, NULL, opt },
    UNIFYCR_CONFIGS
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
    { NULL, 0, NULL, 0 }
};

// update config struct based on command line args
int unifycr_config_process_cli_args(unifycr_cfg_t *cfg,
                                    int argc,
                                    char **argv)
{
    int rc, c;
    int usage_err = 0;
    int ondx = 0;
    int sndx = 0;
    char errmsg[UNIFYCR_CFG_MAX_MSG];
    char short_opts[256];
    extern char *optarg;
    extern int optind, optopt;

    if (cfg == NULL)
        return -1;

    // setup short_opts and cli_options
    memset((void *)short_opts, 0, sizeof(short_opts));
    short_opts[sndx++] = ':'; // report missing args

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    short_opts[sndx++] = opt;                                   \
    if (strcmp(#typ, "BOOL") == 0) {                            \
        short_opts[sndx++] = ':';                               \
        short_opts[sndx++] = ':';                               \
        cli_options[ondx++].has_arg = optional_argument;        \
    }                                                           \
    else {                                                      \
        short_opts[sndx++] = ':';                               \
        cli_options[ondx++].has_arg = required_argument;        \
    }
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    short_opts[sndx++] = opt;                                           \
    if (strcmp(#typ, "BOOL") == 0) {                                    \
        short_opts[sndx++] = ':';                                       \
        short_opts[sndx++] = ':';                                       \
        cli_options[ondx++].has_arg = optional_argument;                \
    }                                                                   \
    else {                                                              \
        short_opts[sndx++] = ':';                                       \
        cli_options[ondx++].has_arg = required_argument;                \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    //fprintf(stderr, "FAMFS CONFIG DEBUG: short-opts '%s'\n", short_opts);

    // process argv
    while ((c = getopt_long(argc, argv, short_opts, cli_options, NULL)) != -1) {
        switch (c) {

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
        case opt: {                                             \
            if (optarg) {                                       \
                if (cfg->sec##_##key != NULL)                   \
                    free(cfg->sec##_##key);                     \
                cfg->sec##_##key = strdup(optarg);              \
            }                                                   \
            else if (strcmp(#typ, "BOOL") == 0) {               \
                if (cfg->sec##_##key != NULL)                   \
                    free(cfg->sec##_##key);                     \
                cfg->sec##_##key = strdup("on");                \
            }                                                   \
            break;                                              \
        }

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
        case opt: {                                                     \
            if (cfg->sec##_##key[cfg->n_##sec##_##key] != NULL)         \
                free(cfg->sec##_##key[cfg->n_##sec##_##key]);           \
            cfg->sec##_##key[cfg->n_##sec##_##key++] = strdup(optarg);  \
            break;                                                      \
        }

        UNIFYCR_CONFIGS
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

        case ':':
            usage_err = 1;
            snprintf(errmsg, sizeof(errmsg),
                     "CLI option -%c requires operand", optopt);
            break;
        case '?':
            usage_err = 1;
            snprintf(errmsg, sizeof(errmsg),
                     "unknown CLI option -%c", optopt);
            break;
        default:
            // should not reach here
            fprintf(stderr, "FAMFS CONFIG DEBUG: unhandled option '%s'\n", optarg);
            break;
        }
        if (usage_err)
            break;
    }

    if (!usage_err)
        rc = 0;
    else {
        rc = -1;
        unifycr_config_cli_usage_error(argv[0], errmsg);
    }

    return rc;
}

// helper to check environment variable
char *getenv_helper(const char *section,
                    const char *key,
                    unsigned mentry)
{
    static char envname[256];
    unsigned u;
    size_t len;
    size_t ndx = 0;

    memset((void *)envname, 0, sizeof(envname));


    ndx += sprintf(envname, "UNIFYCR_");

    if (strcmp(section, "unifycr") != 0) {
        len = strlen(section);
        for (u = 0; u < len; u++)
            envname[ndx + u] = toupper(section[u]);
        ndx += len;
        envname[ndx++] = '_';
    }

    len = strlen(key);
    for (u = 0; u < len; u++)
        envname[ndx + u] = toupper(key[u]);
    ndx += len;

    if (mentry)
        ndx += sprintf(envname + ndx, "_%u", mentry);

    //fprintf(stderr, "FAMFS CONFIG DEBUG: checking env var %s\n", envname);
    return getenv(envname);
}


// update config struct based on environment variables
int unifycr_config_process_environ(unifycr_cfg_t *cfg)
{
    char *envval;

    if (cfg == NULL)
        return -1;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)       \
    envval = getenv_helper(#sec, #key, 0);              \
    if (envval != NULL) {                               \
        if (cfg->sec##_##key != NULL)                   \
            free(cfg->sec##_##key);                     \
        cfg->sec##_##key = strdup(envval);              \
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    envval = getenv_helper(#sec, #key, 0);                      \
    if (envval != NULL) {                                       \
        if (cfg->sec##_##key != NULL)                           \
            free(cfg->sec##_##key);                             \
        cfg->sec##_##key = strdup(envval);                      \
    }

/* FIXME: Now we can't get multi-section vars from ENV */
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    for (u = 0; u < me; u++) {                                          \
        envval = getenv_helper(#sec, #key, u+1);                        \
        if (envval != NULL) {                                           \
            if (cfg->sec##_##key[u] != NULL)                            \
                free(cfg->sec##_##key[u]);                              \
            cfg->sec##_##key[u] = strdup(envval);                       \
            cfg->n_##sec##_##key++;                                     \
        }                                                               \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    return 0;
}

// inih callback handler
int inih_config_handler(void *user,
                        const char *section,
                        const char *kee,
                        const char *val)
{
    char *curval;
    char *defval;
    unifycr_cfg_t *cfg = (unifycr_cfg_t *) user;
    assert(cfg != NULL);

    /* Set current section index */
    if (kee == NULL) {
	if (val)
	    cfg->sec_i = 0;
	else
	    cfg->sec_i++;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)
#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)	\
	    cfg->n_##sec##_##key = 0;
#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)
	UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
	return 1;
    }

    // if not already set by CLI args, set cfg cfgs
    if (0)
	;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)		\
    else if ((strcmp(section, #sec) == 0) &&			\
	     (strcmp(kee, #key) == 0)) {			\
	curval = cfg->sec##_##key;				\
	defval = stringify(dv);					\
	if (curval == NULL)					\
	    cfg->sec##_##key = strdup(val);			\
	else if (strcmp(defval, curval) == 0) {			\
	    free(cfg->sec##_##key);				\
	    cfg->sec##_##key = strdup(val);			\
	}							\
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)	\
    else if ((strcmp(section, #sec) == 0) &&			\
	     (strcmp(kee, #key) == 0)) {			\
	curval = cfg->sec##_##key;				\
	defval = stringify(dv);					\
	if (curval == NULL)					\
	    cfg->sec##_##key = strdup(val);			\
	else if (strcmp(defval, curval) == 0) {			\
	    free(cfg->sec##_##key);				\
	    cfg->sec##_##key = strdup(val);			\
	}							\
    }

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    else if ((strcmp(section, #sec) == 0) &&				\
	     (strcmp(kee, #key) == 0)) {				\
	char **v =							\
	    &cfg->sec##_##key[cfg->sec_i][cfg->n_##sec##_##key];	\
	curval = *v;							\
	defval = stringify(dv);						\
	if (curval && strcmp(defval, curval) == 0) {			\
	    free(*v);							\
	}								\
	*v = (!strcmp(#typ,"STRING") && val[0]=='\"' && strlen(val)>1)?	\
	     strndup(val+1, strlen(val)-2) : strdup(val);		\
	cfg->n_##sec##_##key++;						\
    }

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    else if ((strcmp(section, #sec) == 0) && (strcmp(kee, #key) == 0)) { \
        cfg->sec##_##key[cfg->n_##sec##_##key++] = strdup(val);         \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    return 1;
}

// update config struct based on config file, using inih
int unifycr_config_process_ini_file(unifycr_cfg_t *cfg,
                                    const char *file)
{
    int rc, inih_rc;
    char errmsg[UNIFYCR_CFG_MAX_MSG];

    if (cfg == NULL)
        return EINVAL;

    if (file == NULL)
        return EINVAL;

    inih_rc = ini_parse(file, inih_config_handler, cfg);
    switch (inih_rc) {
    case 0:
        rc = 0;
        break;
    case -1:
        snprintf(errmsg, sizeof(errmsg),
                 "failed to open config file %s",
                 file);
        fprintf(stderr, "FAMFS CONFIG ERROR: %s\n", errmsg);
        rc = ENOENT;
        break;
    case -2:
        snprintf(errmsg, sizeof(errmsg),
                 "failed to parse config file %s",
                 file);
        fprintf(stderr, "FAMFS CONFIG ERROR: %s\n", errmsg);
        rc = ENOMEM;
        break;
    default:
        /* > 0  indicates parse error at line */
        if (inih_rc > 0)
            snprintf(errmsg, sizeof(errmsg),
                     "parse error at line %d of config file %s",
                     inih_rc, file);
        else
            snprintf(errmsg, sizeof(errmsg),
                     "failed to parse config file %s",
                     file);
        rc = EINVAL;
        fprintf(stderr, "FAMFS CONFIG ERROR: %s\n", errmsg);
        break;
    }

    return rc;
}


/* predefined validation functions */

// utility routine to validate a single value given function
int validate_value(const char *section,
                   const char *key,
                   const char *val,
                   const char *typ,
                   configurator_validate_fn vfn,
                   char **new_val)
{
    if (vfn != NULL)
        return vfn(section, key, val, new_val);
    else if (strcmp(typ, "BOOL") == 0)
        return configurator_bool_check(section, key, val, NULL);
    else if (strcmp(typ, "INT") == 0)
        return configurator_int_check(section, key, val, new_val);
    else if (strcmp(typ, "FLOAT") == 0)
        return configurator_float_check(section, key, val, new_val);

    return 0;
}


// validate configuration
int unifycr_config_validate(unifycr_cfg_t *cfg)
{
    int rc = 0;
    int vrc;
    char *new_val = NULL;

    if (cfg == NULL)
        return EINVAL;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)                       \
    vrc = validate_value(#sec, #key, cfg->sec##_##key, #typ, vfn, &new_val); \
    if (vrc) {                                                          \
        rc = vrc;                                                       \
        fprintf(stderr, "FAMFS CONFIG ERROR: %s value '%s' for %s.%s is INVALID %s\n", \
                #dv, cfg->sec##_##key, #sec, #key, #typ);               \
    }                                                                   \
    else if (new_val != NULL) {                                         \
        if (cfg->sec##_##key != NULL)                                   \
            free(cfg->sec##_##key);                                     \
        cfg->sec##_##key = new_val;                                     \
        new_val = NULL;                                                 \
    }

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)         \
    vrc = validate_value(#sec, #key, cfg->sec##_##key, #typ, vfn, &new_val); \
    if (vrc) {                                                          \
        rc = vrc;                                                       \
        fprintf(stderr, "FAMFS CONFIG ERROR: %s value '%s' for %s.%s is INVALID %s\n", \
                #dv, cfg->sec##_##key, #sec, #key, #typ);               \
    }                                                                   \
    else if (new_val != NULL) {                                         \
        if (cfg->sec##_##key != NULL)                                   \
            free(cfg->sec##_##key);                                     \
        cfg->sec##_##key = new_val;                                     \
        new_val = NULL;                                                 \
    }

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)			\
    for (unsigned uu=0; uu < F_CFG_MSEC_MAX; uu++) {				\
	for (unsigned u=0; u < (me>0?me:F_CFG_MSKEY_MAX); u++) {		\
	    char **v = &cfg->sec##_##key[uu][u];				\
	    if (*v != NULL) {							\
		vrc = validate_value(#sec, #key, *v, #typ, vfn, &new_val);	\
		if (vrc) {							\
		    rc = vrc;							\
		    fprintf(stderr, "FAMFS CONFIG ERROR: "			\
			    "value '%s' for %s[%u].%s[%u] is INVALID %s\n",	\
			    *v, #sec, uu, #key, u, #typ);			\
		} else if (new_val != NULL) {					\
		    if (*v != NULL)						\
			free(*v);						\
		    *v = new_val;						\
		    new_val = NULL;						\
		}								\
	    }									\
	}									\
    }

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)   \
    for (u = 0; u < me; u++) {                                          \
        vrc = validate_value(#sec, #key, cfg->sec##_##key[u], #typ, vfn, &new_val); \
        if (vrc) {                                                      \
            rc = vrc;                                                   \
            fprintf(stderr, "FAMFS CONFIG ERROR: value[%u] '%s' for %s.%s is INVALID %s\n", \
                    u+1, cfg->sec##_##key[u], #sec, #key, #typ);        \
        }                                                               \
        else if (new_val != NULL) {                                     \
            if (cfg->sec##_##key[u] != NULL)                            \
                free(cfg->sec##_##key[u]);                              \
            cfg->sec##_##key[u] = new_val;                              \
            new_val = NULL;                                             \
        }                                                               \
    }

    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    return rc;
}

int configurator_bool_val(const char *val,
                          bool *b)
{
    if ((val == NULL) || (b == NULL))
        return EINVAL;

    if (1 == strlen(val)) {
        switch (val[0]) {
        case '0':
        case 'f':
        case 'n':
        case 'F':
        case 'N':
            *b = false;
            return 0;
        case '1':
        case 't':
        case 'y':
        case 'T':
        case 'Y':
            *b = true;
            return 0;
        default:
            return 1;
        }
    }
    else if ((strcmp(val, "no") == 0)
              || (strcmp(val, "off") == 0)
              || (strcmp(val, "false") == 0)) {
        *b = false;
        return 0;
    }
    else if ((strcmp(val, "yes") == 0)
              || (strcmp(val, "on") == 0)
              || (strcmp(val, "true") == 0)) {
        *b = true;
        return 0;
    }
    return EINVAL;
}

int configurator_bool_check(const char *s __attribute__ ((unused)),
                            const char *k __attribute__ ((unused)),
                            const char *val,
                            char **o __attribute__ ((unused)))
{
    bool b;

    if (val == NULL) // unset is OK
        return 0;

    return configurator_bool_val(val, &b);
}

int configurator_float_val(const char *val,
                           double *d)
{
    int err;
    double check;
    char *end = NULL;

    if ((val == NULL) || (d == NULL))
        return EINVAL;

    te_expr *expr = te_compile(val, NULL, 0, &err);
    if (expr) {
        check = te_eval(expr);
        te_free(expr);
    }
    else {
        errno = 0;
        check = strtod(val, &end);
        if ((errno != ERANGE) && (end != val)) {
            switch (*end) {
            case 'f':
            case 'l':
            case 'F':
            case 'L':
                err = 0;
                break;
            default:
                err = end - val;
            }
        }
    }
    if (err) {
        fprintf(stderr, "\t%s\n\t%*s^\n", val, err-1, "");
        return EINVAL;
    }

    *d = check;
    return 0;
}

int configurator_float_check(const char *s __attribute__ ((unused)),
                             const char *k __attribute__ ((unused)),
                             const char *val,
                             char **o)
{
    int rc;
    double d;

    if (val == NULL) // unset is OK
        return 0;

    rc = configurator_float_val(val, &d);
    if ((o != NULL) && (rc == 0)) {
        // update config setting to evaluated value
        size_t len = snprintf(NULL, 0, "%.6le", d) + 1;
        char *newval = (char*) calloc(len, sizeof(char));
        if (newval != NULL) {
            snprintf(newval, len, "%.6le", d);
            *o = newval;
        }
    }
    return rc;
}

int configurator_int_val(const char *val,
                         long *l)
{
    long check;
    int err;
    char *end = NULL;

    if ((val == NULL) || (l == NULL))
        return EINVAL;

    te_expr *expr = te_compile(val, NULL, 0, &err);
    if (expr) {
        double c = te_eval(expr);
        te_free(expr);
        check = (long)c;
        /* In range? */
        if (c != (double)check)
            err = strlen(val);
    }
    else {
        errno = 0;
        check = strtol(val, &end, 0);
        if ((errno != ERANGE) && (end != val)) {
            switch (*end) {
            case 'l':
            case 'u':
            case 'L':
            case 'U':
                err = 0;
                break;
            default:
                err = end - val;
            }
        }
    }
    if (err) {
        fprintf(stderr, "\t%s\n\t%*s^\n", val, err-1, "");
        return EINVAL;
    }

    *l = check;
    return 0;
}

int configurator_int_check(const char *s __attribute__ ((unused)),
                           const char *k __attribute__ ((unused)),
                           const char *val,
                           char **o)
{
    int rc;
    long l;

    if (val == NULL) // unset is OK
        return 0;

    rc = configurator_int_val(val, &l);
    if ((o != NULL) && (rc == 0)) {
        size_t len = snprintf(NULL, 0, "%ld", l) + 1;
        // update config setting to evaluated value
        char *newval = (char*) calloc(len, sizeof(char));
        if (newval != NULL) {
            snprintf(newval, len, "%ld", l);
            *o = newval;
        }
    }
    return rc;
}

int configurator_file_check(const char *s __attribute__ ((unused)),
                            const char *k,
                            const char *val,
                            char **o)
{
    const char *p;
    int rc;
    struct stat st;

    if (val == NULL)
        return 0;

    rc = stat(val, &st);
    if (rc != 0) {
	rc = errno;
	if (rc != EPERM && rc != ENOENT)
	    return errno; // invalid
    } else if (st.st_mode & S_IFREG)
	return 0;

    /* try to look for the file in current dir */
    p = val;
    p = strrchr(p, '/');
    if (p == NULL)
	goto _no_file;
    rc = stat(++p, &st);
    if (rc != 0) {
	rc = errno;
	if (rc == EPERM || rc == ENOENT)
	    goto _no_file;
	return errno; // invalid
    }
    if (!(st.st_mode & S_IFREG))
	goto _no_file;
    *o = strdup(p);
    return 0;

_no_file:
    /* Return error to ini file parser otherwise Ok */
    return (k == NULL)? ENOENT : 0;
}

int configurator_directory_check(const char *s __attribute__ ((unused)),
                                 const char *k __attribute__ ((unused)),
                                 const char *val,
                                 char **o __attribute__ ((unused)))
{
    int mode, rc;
    struct stat st;

    if (val == NULL)
        return 0;

    // check dir exists
    rc = stat(val, &st);
    if (rc == 0) {
        if (st.st_mode & S_IFDIR)
            return 0;
        else
            return ENOTDIR;
    }
    else { // try to create it
        mode = 0770; // S_IRWXU | S_IRWXG
        rc = mkdir(val, mode);
        if (rc == 0)
            return 0;
        else
            return errno; // invalid
    }
}

int configurator_moniker_check(const char *s __attribute__ ((unused)),
                               const char *k __attribute__ ((unused)),
                               const char *val,
                               char **o __attribute__ ((unused)))
{
    size_t chunk_size;
    int data, parity, mirrors, rc;

    if (val) {
	rc = f_parse_moniker(val, &data, &parity, &mirrors, &chunk_size);
	if (mirrors || rc)
		return -1;
    }
    return 0; /* pass null strings */
}

int configurator_uuid_check(const char *s __attribute__ ((unused)),
                               const char *k __attribute__ ((unused)),
                               const char *val,
                               char **o __attribute__ ((unused)))
{
    /* null string is Ok */
    return f_parse_uuid(val, NULL);
}

/* Parse UUID version 4 string to 128-bit value */
int f_parse_uuid(const char *s, uuid_t *uuid_p) {
    union {
	uint128_t uuid;
	struct {
	    uint32_t	d1;
	    uint16_t	d2;
	    uint16_t	d3;
	    uint8_t	d4[8];
	} __attribute__((packed));
    } u;
    int rc;

    if (s == NULL)
	return 0; /* null string is Ok */
    if (*s == '{')
	s++;
    rc = sscanf(s, "%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
	&u.d1, &u.d2, &u.d3, &u.d4[0], &u.d4[1],
	&u.d4[2], &u.d4[3], &u.d4[4], &u.d4[5], &u.d4[6], &u.d4[7]);
    if (rc == 0)
	return -1;
    if (rc == 11) {
	if ((u.d3 & 0xf000) == 0x4000 && (u.d4[0] & 0xc0) == 0x80) {
	    if (uuid_p)
		*(uint128_t *)uuid_p = u.uuid;
	    return 0; /* Valid UUID */
	}
	return -2; /* Not an UUID version 4 */
    }
    return rc;
}

int check_multisec(unifycr_cfg_t *cfg, const char *cursec)
{
    //char *sec##_##key[F_CFG_MSEC_MAX][1]
    unsigned int i, ids, n;
    int rc = 0;

    ids = n = 0; /* ids starts with zero by default */

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)
#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    if (!strcmp(cursec, #sec)) {					\
	if (!strcmp("id", #key)) {					\
	    n = 0; /* "id" key should go the first in the section */	\
	    for (i = 0; i < F_CFG_MSEC_MAX; i++) {			\
		char *v = cfg->sec##_##key[i][0];			\
		if (strcmp("INT", #typ)) {				\
		    rc = 1;						\
		    fprintf(stderr, "FAMFS CONFIG ERROR: "		\
			    "value for %s.%s has INVALID type:%s\n",	\
			    #sec, #key, #typ);				\
		} else if (i == 0) {					\
		    n = ids = v? strtoul(v, NULL, 10) : 0;		\
		} else if (v && strtoul(v,NULL,10) != (n = (i+ids))) {	\
		    rc = 2;						\
		    fprintf(stderr, "FAMFS CONFIG ERROR: "		\
			    "value '%s' for %s[%u].%s is INVALID %s\n",	\
			    v, #sec, i, #key, #typ);			\
		}							\
	    }								\
	} else {							\
	    for (i = 0; i < F_CFG_MSEC_MAX; i++) {			\
		if (cfg->sec##_##key[i][0] && (i + ids > n))		\
		    n = i + ids;					\
	    }								\
	}								\
    }
#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)
    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG_MULTI
    if (rc)
	return rc;

    /* Set ids */
    n -= ids;
    assert (n < F_CFG_MSEC_MAX);
    _Static_assert (F_CFG_MSEC_MAX < 1000U, "F_CFG_MSEC_MAX too big");

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    if (!strcmp(cursec, #sec) && !strcmp("id", #key)) {			\
	for (i = 0; i <= n; i++) {					\
	    char **vp = &cfg->sec##_##key[i][0];			\
	    if (*vp && strtoul(*vp, NULL, 10) != (i + ids)) {		\
		free(*vp); *vp = NULL;					\
	    }								\
	    if (*vp == NULL) {						\
		*vp = malloc(4);					\
		snprintf(*vp, 4, "%u", i+ids);				\
	    }								\
	}								\
    }
    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
    return 0;
}

int famfs_config_check_multisec(unifycr_cfg_t *cfg)
{
    char *cursec = NULL;
    int src, rc = 0;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)
#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)	\
    if (!cursec || strcmp(cursec, #sec)) {			\
	free(cursec);						\
	cursec = strdup( #sec );				\
	src = check_multisec(cfg, cursec);			\
	if (src && !rc)						\
	    rc = src; /* report the first error */		\
    }
#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)
    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
    return rc;
}

/* Return actual section size and key list size under section
 * at given index in *keylist_size,
 * given section name 'section', key 'kee' and the index.
 */
int configurator_get_sizes(unifycr_cfg_t *cfg,
			   const char *section,
			   const char *kee,
			   int *keylist_size)
{
    int i, j, m, s;
    int size=0, kl_size=0;

    /* section index for keylist size if any */
    s = (keylist_size)? *keylist_size : -1;

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn)
#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use)
#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)	\
    if (!strcmp(section, #sec)) {				\
	if (!strcmp("id", #key)) {				\
	    size = F_CFG_MSEC_MAX;				\
	    for (i = m = 0; i < size; i++) {			\
		if (cfg->sec##_##key[i][0])			\
		    m = i + 1;					\
	    }							\
	    size = m;						\
	    kl_size = me>0? me:F_CFG_MSKEY_MAX;			\
	}							\
	if (kee && !strcmp(kee, #key)) {			\
	    kl_size = me>0? me:F_CFG_MSKEY_MAX;			\
	    for (i = m = 0; i < size; i++) {			\
		if (s >= 0 && s != i)				\
		    continue;					\
		for (j = 0; j < kl_size; j++) {			\
		    if (cfg->sec##_##key[i][j])			\
			    m = j + 1;				\
		}						\
	    }							\
	    kl_size = m;					\
	}							\
    }
#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, desc, vfn, me, opt, use)
    UNIFYCR_CONFIGS;
#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI

    if (keylist_size)
	*keylist_size = kl_size;
    return size;
}

