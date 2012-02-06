
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_cache.h>

static ngx_str_t  ngx_http_fastcgi_cache_post_method = {4, (u_char *)"POST "};
static ngx_str_t  ngx_http_fastcgi_cache_content_length_header_key =
        ngx_string("Content-Length");

void
ngx_http_fastcgi_cache_drop_output(ngx_http_request_t *r)
{
    ngx_http_request_t              *parent;
    ngx_http_postponed_request_t    *pr, **ppr;
    ngx_chain_t                     *cl, **pcl;

    parent = r->parent;
    if (!parent || parent == r) {
        /* r is not a subrequest */
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_fastcgi_cache_drop_output for %v",
                   &parent->uri);

    ppr = &parent->postponed;
    for (pr = parent->postponed; pr; pr = pr->next) {

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "postponed request for %V: request:%p r:%p, parent:%p",
                &parent->uri, pr->request, r, parent);

        if (pr->request == r) {
           *ppr = pr->next;
        }
        ppr = &pr->next;

    }

    pcl = &parent->out;
    for (cl = parent->out; cl; cl = cl->next) {

#if (NGX_DEBUG)
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "parent out buffer "
                          "t:%d r:%d f:%d m:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->memory,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);
#endif /* NGX_DEBUG */

        if (!ngx_buf_special(cl->buf))
            *pcl = cl->next;

        pcl = &cl->next;
    }

}

#if (NGX_DEBUG)
static void
ngx_http_fastcgi_cache_dump_postponed(ngx_http_request_t *r)
{
    ngx_http_postponed_request_t    *pr;
    ngx_uint_t                       i;
    ngx_str_t                        out;
    size_t                           len;
    ngx_chain_t                     *cl;
    u_char                          *p;
    ngx_str_t                        nil_str;

    ngx_str_set(&nil_str, "(nil)");

    for (i = 0, pr = r->postponed; pr; pr = pr->next, i++) {
        out.data = NULL;
        out.len = 0;

        len = 0;
        for (cl = pr->out; cl; cl = cl->next) {
            len += ngx_buf_size(cl->buf);
        }

        if (len) {
            p = ngx_palloc(r->pool, len);
            if (p == NULL) {
                return;
            }

            out.data = p;

            for (cl = pr->out; cl; cl = cl->next) {
                p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
            }

            out.len = len;
        }

        ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "postponed request for %V: "
                "c:%d, "
                "a:%d, i:%d, r:%V, out.len:%d",
                &r->uri,
                r->main->count,
                r == r->connection->data, i,
                pr->request ? &pr->request->uri : &nil_str, out.len);
    }
}
#endif /* NGX_DEBUG */

static ngx_int_t
ngx_http_fastcgi_cache_subreq_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t            *pr;
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;

    pr = r->parent;

    c = pr->cache;
    priv = c->cache_priv;

#if (NGX_DEBUG)
    ngx_http_fastcgi_cache_dump_postponed(pr);
#endif /* NGX_DEBUG */

    if (r->headers_out.status != NGX_HTTP_OK) {
        /* Drop buffers related to this subrequest */
        ngx_http_fastcgi_cache_drop_output(r);
        priv->state = fastcgi_not_found;
        return NGX_OK;
    }

    if (r->upstream) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache len: %d data: \"%s\", status: %d",
                       r->upstream->buffer.last - r->upstream->buffer.pos, r->upstream->buffer.pos, r->headers_out.status);
    }
    priv->state = fastcgi_read_data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_fastcgi_cache_set_content_length_header(ngx_http_request_t *r, off_t len)
{
    ngx_table_elt_t            *h;

    r->headers_in.content_length_n = len;
    r->headers_in.content_length = ngx_pcalloc(r->pool,
            sizeof(ngx_table_elt_t));

    r->headers_in.content_length->value.data =
        ngx_palloc(r->pool, NGX_OFF_T_LEN);

    if (r->headers_in.content_length->value.data == NULL) {
        return NGX_ERROR;
    }

    r->headers_in.content_length->value.len = ngx_sprintf(
            r->headers_in.content_length->value.data, "%O",
            r->headers_in.content_length_n) -
            r->headers_in.content_length->value.data;

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                sizeof(ngx_table_elt_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = r->header_hash;

    h->key = ngx_http_fastcgi_cache_content_length_header_key;
    h->value = r->headers_in.content_length->value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "r content length: %V",
            &r->headers_in.content_length->value);

    return NGX_OK;
}

static void
ngx_http_fastcgi_cache_create_url(ngx_http_request_t *r, ngx_str_t *out, ngx_uint_t upload)
{
    ngx_http_file_cache_t         *cache_conf;
    ngx_http_fastcgi_cache_priv_t *priv;
    u_char                        *p;
    ngx_str_t                      get_url = ngx_string("/get/");
    ngx_str_t                      upload_url = ngx_string("/upload/");

    priv = r->cache->cache_priv;
    cache_conf = r->upstream->conf->cache->data;

    out->len = cache_conf->path->name.len;
    out->len += priv->cache_url.len;
    out->len += upload?upload_url.len:get_url.len;

    out->data = ngx_palloc(r->pool, out->len);
    if (out->data == NULL) {
        return;
    }

    p = out->data;
    p = ngx_copy(p, cache_conf->path->name.data, cache_conf->path->name.len);
    if (upload) {
        p = ngx_copy(p, upload_url.data, upload_url.len);
    } else {
        p = ngx_copy(p, get_url.data, get_url.len);
    }
    p = ngx_copy(p, priv->cache_url.data, priv->cache_url.len);
}

void
ngx_http_fastcgi_cache_init(ngx_http_cache_t *c, ngx_http_upstream_t *u){
    return;
}

ngx_int_t
ngx_http_fastcgi_cache_new(ngx_http_request_t *r)
{
    ngx_http_cache_t  *c;
    ngx_http_fastcgi_cache_priv_t *priv;

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->cache_priv = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_cache_priv_t));
    if (c->cache_priv == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&c->keys, r->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    r->cache = c;
    c->file.log = r->connection->log;
    c->file.fd = NGX_INVALID_FILE;
    c->exists = 1;

    priv = c->cache_priv;
    priv->state = fastcgi_emit_subrequest;

    return NGX_OK;
}

ngx_int_t
ngx_http_fastcgi_cache_create(ngx_http_request_t *r)
{
    return NGX_OK;
}

void
ngx_http_fastcgi_cache_create_key(ngx_http_request_t *r)
{
    size_t                         len;
    ngx_str_t                     *key;
    ngx_uint_t                     i;
    u_char                        *p;
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;
    //ngx_http_file_cache_t         *cache_conf;

    c = r->cache;
    priv = c->cache_priv;

    //cache_conf = r->upstream->conf->cache->data;
    
    //len = cache_conf->path->name.len + 1;
    len = 0;
    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cache key: \"%V\"", &key[i]);

        len += key[i].len;
    }

    priv->cache_url.data = ngx_palloc(r->pool, len);
    if (!priv->cache_url.data) {
        return;
    }

    p = priv->cache_url.data;

    //p = ngx_copy(p, cache_conf->path->name.data, cache_conf->path->name.len);
    //*p = '/';
    //p++;

    for (i = 0; i < c->keys.nelts; i++) {
        p = ngx_copy(p, key[i].data, key[i].len);
    }

    priv->cache_url.len = len;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache url : \"%V\"",
                   &priv->cache_url);

    return;
}

ngx_int_t
ngx_http_fastcgi_cache_open(ngx_http_request_t *r)
{
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *psr;
    ngx_str_t                      uri;
    ngx_int_t                      rc = NGX_AGAIN;

    c = r->cache;
    priv = c->cache_priv;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache open: state:%d", priv->state);

    if (priv->state == fastcgi_not_found) {
        r->main->method = priv->orig_method;
        r->main->method_name = priv->orig_method_name;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache status: %d", NGX_DECLINED);
        return NGX_DECLINED;
    }

    if (priv->state == fastcgi_emit_subrequest) {
        priv->state = fastcgi_read_header;

        ngx_http_fastcgi_cache_create_url(r, &uri, 0);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache open: uri: %V", &uri);

        psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (psr == NULL) {
            return NGX_ERROR;
        }

        psr->handler = ngx_http_fastcgi_cache_subreq_handler;
        psr->data = NULL;

        rc = ngx_http_subrequest(r, &uri, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_WAITED);
        /* Overwrite main request method name for fastcgi module */
        priv->orig_method = sr->main->method;
        priv->orig_method_name = sr->main->method_name;
        sr->main->method = NGX_HTTP_GET;
        sr->main->method_name = ngx_http_core_get_method;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache subrequest rc: %d", rc);

        if (rc == NGX_OK)
            rc = NGX_AGAIN;
    }

    if (priv->state == fastcgi_read_data) {
        c->header_start = c->body_start;
        rc = NGX_OK;
    }

    return rc;
}

void
ngx_http_fastcgi_cache_set_header(ngx_http_request_t *r, u_char *buf)
{
    return;
}

static ngx_int_t
ngx_http_fastcgi_cache_upd_subreq_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t            *pr;
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;
    ngx_str_t                      nil_str = ngx_string("(nil)");

    pr = r->parent;

    c = pr->cache;
    priv = c->cache_priv;

#if (NGX_DEBUG)
    ngx_http_fastcgi_cache_dump_postponed(pr);
#endif /* NGX_DEBUG */

    if (r->upstream) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache len: %d data: \"%s\", status: %d",
                       r->upstream->buffer.last - r->upstream->buffer.pos, r->upstream->buffer.pos?r->upstream->buffer.pos:nil_str.data, r->headers_out.status);
    }

    return NGX_OK;
}

void
ngx_http_fastcgi_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf)
{
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *psr;
    ngx_str_t                      uri;
    ngx_int_t                      rc;
    ngx_buf_t                     *b;
    ngx_file_info_t                fi;
    off_t                          len;

    ngx_http_fastcgi_cache_create_url(r, &uri, 1);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache open: uri: %V", &uri);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache update for %V, temp file %V",
                   &r->uri, &tf->file.name);

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return;
    }

    psr->handler = ngx_http_fastcgi_cache_upd_subreq_handler;
    psr->data = NULL;

    rc = ngx_http_subrequest(r, &uri, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_WAITED);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache update subrequest rc: %d", rc);

    sr->method = NGX_HTTP_POST;
    sr->method_name = ngx_http_fastcgi_cache_post_method;
    /* Overwrite main request method name for fastcgi module */
    sr->main->method_name = ngx_http_fastcgi_cache_post_method;

    if (ngx_fd_info(tf->file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", tf->file.name.data);
        return;
    }

    sr->request_body->bufs = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (sr->request_body->bufs == NULL) {
        return;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return;
    }

    b->file = &tf->file;

    b->file_pos = 0;//tf->offset;
    b->file_last = ngx_file_size(&fi);
    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;
    len = b->file_last-b->file_pos;

    sr->request_body->bufs->buf = b;
    sr->request_body->bufs->next = NULL;
    sr->discard_body = 0;

    rc = ngx_http_fastcgi_cache_set_content_length_header(sr, len);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache sending file %V, %d bytes starting from %d, discard_body %d",
                   &tf->file.name, (int)(b->file_last-b->file_pos), (int)(b->file_pos), sr->discard_body);
    
    return;
}

ngx_int_t
ngx_http_fastcgi_cache_send(ngx_http_request_t *r)
{
    ngx_chain_t                    out;

    out.buf = ngx_calloc_buf(r->pool);
    if (out.buf == NULL) {
        return NGX_ERROR;
    }

    out.buf->last_buf = 1;
    out.buf->last_in_chain = 1;

    out.next = NULL;
    ngx_http_output_filter(r, &out);
    return NGX_OK;
}

void
ngx_http_fastcgi_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf)
{
    ngx_delete_file(tf->file.name.data);
    return;
}

char *
ngx_http_fastcgi_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
/*
    ngx_str_t                       s, *value;
    ssize_t                         size;
    u_char                         *p;
    ngx_uint_t                      i;
    ngx_shm_zone_t                 *shm_zone;
    ngx_http_fastcgi_cache_conf_t  *cache_conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_http_fastcgi_cache_set_slot");

    cache_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_cache_conf_t));
    if (cache_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    cache_conf->location = value[1];
    size = 0;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            cache_conf->zone.data = value[i].data + 10;

            p = (u_char *) ngx_strchr(cache_conf->zone.data, ':');

            if (p) {
                *p = '\0';

                cache_conf->zone.len = p - cache_conf->zone.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid keys zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "levels=", 7) == 0) {
            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
            continue;
        }

        if (ngx_strncmp(value[i].data, "max_size=", 9) == 0) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (cache_conf->zone.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &cache_conf->zone, 1, cmd->post);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = NULL;
    shm_zone->data = cache_conf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http fastcgi cache location: \"%V\", zone: \"%V\"",
                   &cache_conf->location, &cache_conf->zone);
*/
    return NGX_CONF_OK;
}
