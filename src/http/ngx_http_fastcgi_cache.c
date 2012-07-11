
/*
 * Copyright (C) Anton Kortunov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_cache.h>

static ngx_str_t  ngx_http_fastcgi_cache_post_method = {4, (u_char *)"POST "};
static ngx_str_t  ngx_http_fastcgi_cache_content_length_header_key =
        ngx_string("Content-Length");

static ngx_int_t ngx_http_fastcgi_cache_output_filter(void *ctx, ngx_chain_t *in);




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
        if (!ngx_buf_special(cl->buf))
            *pcl = cl->next;

        pcl = &cl->next;
    }

}

static ngx_int_t
ngx_http_send_fastcgi_special(ngx_http_request_t *r, ngx_uint_t flags, ngx_event_pipe_output_filter_pt output_filter)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_HTTP_LAST) {

        b->last_buf = 1;
    }

    if (flags & NGX_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return output_filter(r, &out);
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
    //ngx_http_file_cache_header_t  *h;

    pr = r->parent;

    c = pr->cache;
    priv = c->cache_priv;

#if (NGX_DEBUG)
    ngx_http_fastcgi_cache_dump_postponed(pr);
#endif /* NGX_DEBUG */

    if (r->headers_out.status != NGX_HTTP_OK) {
        goto out_exit;
    }

    if (r->upstream && r->upstream->buffer.pos) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache len: %d data: \"%s\", status: %d",
                       r->upstream->buffer.last - r->upstream->buffer.pos, r->upstream->buffer.pos, r->headers_out.status);

        if ((unsigned int)(r->upstream->buffer.last - r->upstream->buffer.pos) < sizeof(ngx_http_file_cache_header_t)) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                          "http fastcgi cache: file it soo small: %d bytes", r->upstream->buffer.last - r->upstream->buffer.pos);
            goto out_exit;
        }

    }

    ngx_http_send_fastcgi_special(r, NGX_HTTP_LAST, ngx_http_fastcgi_cache_output_filter);
    return NGX_OK;
out_exit:
    /* Drop buffers related to this subrequest */
    ngx_http_fastcgi_cache_drop_output(r);
    priv->state = fastcgi_not_found;

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

static ngx_int_t
ngx_http_fastcgi_cache_output_filter(void *ctx, ngx_chain_t *in)
{
    time_t                         now;
    ngx_int_t                      rc = NGX_OK;
    ngx_http_request_t            *sr = (ngx_http_request_t *)ctx;
    ngx_http_request_t            *r = sr->parent;
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;
    ngx_http_file_cache_header_t  *h;


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                   "http fastcgi cache output filter");

    if (!r) {
        ngx_log_error(NGX_LOG_CRIT, sr->connection->log, 0,
                      "http fastcgi cache output filter is called not for subrequest");
        return NGX_ERROR;
    }

    c = r->cache;
    if (!c) {
        ngx_log_error(NGX_LOG_CRIT, sr->connection->log, 0,
                      "http fastcgi cache output filter is called for subrequest without cache in parent");
        return NGX_ERROR;
    }

    priv = c->cache_priv;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                   "http fastcgi cache output filter: state:%d", priv->state);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                   "http fastcgi cache output filter: request status :%d", sr->headers_out.status);

    if (sr->headers_out.status != NGX_HTTP_OK) {
        priv->state = fastcgi_not_found;
        return NGX_OK;
    }

    if (priv->state == fastcgi_send_data) {
        if (priv->in) {
            rc = ngx_http_output_filter(sr, priv->in);
            if (rc != NGX_OK) {
                return rc;
            }
            priv->in = NULL;
        }
        rc = ngx_http_output_filter(sr, in);
        return rc;
    }

    if (priv->state <= fastcgi_read_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache copying data to temp chain");

        if (ngx_chain_add_copy(r->pool, &priv->in, in) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Wake up parent request */
	r->write_event_handler(r);
    }

    if (priv->state == fastcgi_read_header) {
        c->output_ctx = sr;
        if ((ngx_buf_size(priv->in->buf) < (off_t)sizeof(ngx_http_file_cache_header_t)) || !ngx_buf_in_memory(priv->in->buf)) {
	    ngx_log_error(NGX_LOG_CRIT, sr->connection->log, 0,
			  "http fastcgi cache output filter input buffer size is less than cache header size");
            priv->state = fastcgi_not_found;
	    return NGX_OK;
        }
        h = (ngx_http_file_cache_header_t *)priv->in->buf->pos;
        c->header_start = h->header_start;
        c->body_start = h->body_start;
        c->valid_sec = h->valid_sec;
        c->valid_msec = h->valid_msec;
        c->last_modified = h->last_modified;
        c->date = h->date;

        r->cached = 1;
        priv->state = fastcgi_read_header_content;

        now = ngx_time();
        if (c->valid_sec < now) {
            priv->state = fastcgi_expired;
	    ngx_log_error(NGX_LOG_WARN, sr->connection->log, 0,
			  "http fastcgi cache output filter: expired, finalising request");
	    ngx_http_finalize_request(sr, 410);
        } else {
            c->buf = ngx_create_temp_buf(r->pool, c->body_start);
            if (c->buf == NULL) {
                return NGX_ERROR;
            }
        }
    }

    if (priv->state == fastcgi_read_header_content) {
        size_t size;

        while ((size_t)ngx_buf_size(c->buf) < (c->body_start)) {
            size = ngx_min(ngx_buf_size(priv->in->buf), c->buf->end - c->buf->last);
            c->buf->last = ngx_cpymem(c->buf->last, priv->in->buf->pos, size);

            priv->in->buf->pos += size;
            if (size == (size_t)ngx_buf_size(priv->in->buf)) {
                priv->in = priv->in->next;
            } else {
            }
        }

        if ((size_t)ngx_buf_size(c->buf) == c->body_start) {
            priv->state = fastcgi_read_data;
        }
    }

    return rc;
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

    c->output_filter = ngx_http_fastcgi_cache_output_filter;
    c->output_ctx = r;

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

    c->header_start = sizeof(ngx_http_file_cache_header_t);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
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
        c->output_filter = NULL;
        r->main->method = priv->orig_method;
        r->main->method_name = priv->orig_method_name;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache status: %d", NGX_DECLINED);
        return NGX_DECLINED;
    }

    if (priv->state == fastcgi_expired) {
        if (r->upstream->buffering)
            c->output_filter = NULL;
        r->main->method = priv->orig_method;
        r->main->method_name = priv->orig_method_name;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi cache expired: %i %T %T", 
			NGX_HTTP_CACHE_STALE, c->valid_sec, ngx_time());
        return NGX_HTTP_CACHE_STALE;
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
        rc = NGX_OK;
    }

    return rc;
}

void
ngx_http_fastcgi_cache_set_header(ngx_http_request_t *r, u_char *buf)
{
    ngx_http_file_cache_header_t  *h = (ngx_http_file_cache_header_t *) buf;

    u_char            *p;
    //ngx_str_t         *key;
    //ngx_uint_t         i;
    ngx_http_cache_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache set header");

    c = r->cache;

    h->valid_sec = c->valid_sec;
    h->last_modified = c->last_modified;
    h->date = c->date;
    h->crc32 = c->crc32;
    h->valid_msec = (u_short) c->valid_msec;
    h->header_start = (u_short) c->header_start;
    h->body_start = (u_short) c->body_start;

    p = buf + sizeof(ngx_http_file_cache_header_t);

    /*p = ngx_cpymem(p, ngx_http_file_cache_key, sizeof(ngx_http_file_cache_key));

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        p = ngx_copy(p, key[i].data, key[i].len);
    }

    *p = LF;
    */
    return;
}

static ngx_int_t
ngx_http_fastcgi_cache_upd_subreq_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t            *pr;
    ngx_http_cache_t              *c;
    ngx_http_fastcgi_cache_priv_t *priv;
#if (NGX_DEBUG)
    ngx_str_t                      nil_str = ngx_string("(nil)");
#endif /* NGX_DEBUG */

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

    //ngx_http_fastcgi_cache_send(r);
    ngx_http_send_special(r, NGX_HTTP_LAST);
    r->post_action = 1;

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
    //ngx_chain_t        out;
    ngx_http_cache_t  *c;
    ngx_int_t          rc = NGX_OK;
    ngx_http_fastcgi_cache_priv_t *priv;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fastcgi cache send");

    c = r->cache;
    priv = c->cache_priv;
    r->header_only = (c->length - c->body_start) == 0;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    //if (priv->in) {
    //    priv->in->buf->pos += c->body_start;
    //}
    //rc = ngx_http_output_filter(r, priv->in);
    //priv->in = NULL;
    priv->state = fastcgi_send_data;
    //ngx_http_send_special(r, NGX_HTTP_LAST);
/*
    out.buf = ngx_calloc_buf(r->pool);
    if (out.buf == NULL) {
        return NGX_ERROR;
    }

    out.buf->last_buf = 1;
    out.buf->last_in_chain = 1;

    out.next = NULL;
    ngx_http_output_filter(r, &out);
*/
    return rc;
}

void
ngx_http_fastcgi_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf)
{
    if (tf) {
        ngx_delete_file(tf->file.name.data);
    }
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
