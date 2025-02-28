/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * See also support/check_forensic.
 * Relate the forensic log to the transfer log by including
 * %{forensic-id}n in the custom log format, for example:
 * CustomLog logs/custom "%h %l %u %t \"%r\" %>s %b %{forensic-id}n"
 *
 * Credit is due to Tina Bird <tbird precision-guesswork.com>, whose
 * idea this module was.
 *
 *   Ben Laurie 29/12/2003
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "http_protocol.h"
#include "test_char.h"
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA http_headers_module;

typedef struct fcfg
{
    int export_headers;
    int export_headers_set;
} fcfg;

static apr_uint32_t next_id;

void *make_headers_scfg(apr_pool_t *pool, server_rec *s)
{
    fprintf(stdout, "make");
    fcfg *dir_conf = apr_pcalloc(pool, sizeof(fcfg));
    dir_conf->export_headers = 0;
    dir_conf->export_headers_set = 0;
    return dir_conf;
}

void *merge_headers_scfg(apr_pool_t *pool, void *BASE, void *ADD)
{
    fcfg *base = (fcfg *)BASE;
    fcfg *add = (fcfg *)ADD;
    fcfg *conf = (fcfg *)make_headers_scfg(pool, NULL);

    fcfg *src = NULL; // switch between base or add based on which has values set
    src = (add->export_headers_set) ? add : base;
    conf->export_headers = src->export_headers;
    conf->export_headers_set = src->export_headers_set;
    return conf;
}

static const char *enable_envvars(cmd_parms *cmd, void *config, int flag)
{
    fcfg *cfg = ap_get_module_config(cmd->server->module_config,
                                     &http_headers_module);
    cfg->export_headers = (flag ? 1 : 0);
    cfg->export_headers_set = 1;

    return NULL;
}

/* e is the first _invalid_ location in q
   N.B. returns the terminating NUL.
 */
static char *parse_escape(char *q, const char *e, const char *p)
{
    for (; *p; ++p)
    {
        ap_assert(q < e);
        if (test_char_table[*(unsigned char *)p] & T_ESCAPE_FORENSIC)
        {
            ap_assert(q + 2 < e);
            *q++ = '%';
            sprintf(q, "%02x", *(unsigned char *)p);
            q += 2;
        }
        else
            *q++ = *p;
    }
    ap_assert(q < e);
    *q = '\0';

    return q;
}

typedef struct hlog
{
    char *log;
    char *pos;
    char *end;
    apr_pool_t *p;
    apr_size_t count;
} hlog;

static int count_string(const char *p)
{
    int n;

    for (n = 0; *p; ++p, ++n)
        if (test_char_table[*(unsigned char *)p] & T_ESCAPE_FORENSIC)
            n += 2;
    return n;
}

static int count_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    h->count += count_string(key) + count_string(value) + 3;

    return 1;
}

static int parse_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    /* note that we don't have to check h->pos here, coz its been done
       for us by parse_escape */
    *h->pos++ = '\r';
    *h->pos++ = '\n';
    h->pos = parse_escape(h->pos, h->end, key);
    *h->pos++ = ':';
    h->pos = parse_escape(h->pos, h->end, value);

    return 1;
}

static int parse_request_headers(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &http_headers_module);
    apr_table_t *env = r->subprocess_env;
    if (!cfg->export_headers)
    {
        return OK;
    }
    hlog h;
    apr_size_t n;
    apr_status_t rv;

    if (r->prev)
    {
        return DECLINED;
    }

    h.p = r->pool;
    h.count = 0;

    apr_table_do(count_headers, &h, r->headers_in, NULL);

    h.count += count_string(r->the_request) + 1 + 1 + 1 + 1;
    h.log = apr_palloc(r->pool, h.count);
    h.pos = h.log;
    h.end = h.log + h.count;

    h.pos = parse_escape(h.pos, h.end, r->the_request);

    apr_table_do(parse_headers, &h, r->headers_in, NULL);

    ap_assert(h.pos < h.end);
    *h.pos++ = '\n';
    *h.pos++ = '0';

    char *var = "HTTP_HEADERS_ALL";
    apr_table_setn(env, var, h.log);

    return OK;
}

static const command_rec http_headers_cmds[] =
    {
        AP_INIT_FLAG("HTTPHeaderEnvVar", enable_envvars, NULL,
                     ACCESS_CONF | OR_OPTIONS, "Enable creation of http headers environment variable ('on', 'off')"),
        {NULL}};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(parse_request_headers, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

AP_DECLARE_MODULE(http_headers) =
    {
        STANDARD20_MODULE_STUFF,
        NULL,               /* create pre-dir config */
        NULL,               /* merge pre-dir config */
        make_headers_scfg,  /* server config */
        merge_headers_scfg, /* merge server config */
        http_headers_cmds,  /* command apr_table_t */
        register_hooks      /* register hooks */
};