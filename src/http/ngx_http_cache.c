
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_cache.h>


void
ngx_http_cache_init(ngx_http_cache_t *c, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_init(c, u);
    }

    return ngx_http_file_cache_init(c, u);
}

ngx_int_t
ngx_http_cache_new(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_new(r);
    }

    return ngx_http_file_cache_new(r);
}

ngx_int_t
ngx_http_cache_create(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_create(r);
    }

    return ngx_http_file_cache_create(r);
}

void
ngx_http_cache_create_key(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_create_key(r);
    }

    ngx_http_file_cache_create_key(r);
    return;
}

ngx_int_t
ngx_http_cache_open(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_open(r);
    }

    return ngx_http_file_cache_open(r);
}

void
ngx_http_cache_set_header(ngx_http_request_t *r, u_char *buf, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_set_header(r, buf);
    }

    return ngx_http_file_cache_set_header(r, buf);
}

void
ngx_http_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf, ngx_http_upstream_t *u)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cache update: type:%d", u->conf->cache_type);
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_update(r, tf);
    }

    return ngx_http_file_cache_update(r, tf);
}

ngx_int_t
ngx_http_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_send(r);
    }

    return ngx_http_file_cache_send(r);
}

void
ngx_http_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_free(c, tf);
    }

    ngx_http_file_cache_free(c, tf);
    return;
}

time_t
ngx_http_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status, ngx_http_upstream_t *u)
{
    if (u->conf->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_file_cache_valid(cache_valid, status);
    }

    return ngx_http_file_cache_valid(cache_valid, status);
}

char *
ngx_http_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;
    ngx_http_upstream_conf_t *upstream;

    upstream = (ngx_http_upstream_conf_t *) (p + cmd->offset);
    if (upstream->cache_type == NGX_HTTP_CACHE_TYPE_FASTCGI) {
        return ngx_http_fastcgi_cache_set_slot(cf, cmd, conf);
    }

    return ngx_http_file_cache_set_slot(cf, cmd, conf);
}
char *
ngx_http_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    return ngx_http_file_cache_valid_set_slot(cf, cmd, conf);
}


char *
ngx_http_cache_set_type_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *value;
    ngx_flag_t       *fp;
    ngx_conf_post_t  *post;

    fp = (ngx_flag_t *) (p + cmd->offset);

//    if (*fp != NGX_CONF_UNSET) {
//        return "is duplicate";
//    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "file") == 0) {
        *fp = NGX_HTTP_CACHE_TYPE_FILE;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "fastcgi") == 0) {
        *fp = NGX_HTTP_CACHE_TYPE_FASTCGI;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"file\" or \"fastcgi\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return NGX_CONF_OK;
}
