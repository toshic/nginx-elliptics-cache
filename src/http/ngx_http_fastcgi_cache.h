
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_FASTCGI_CACHE_H_INCLUDED_
#define _NGX_HTTP_FASTCGI_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_FASTCGI_CACHE_KEY_LEN       16

enum ngx_http_fastcgi_cache_state {
    fastcgi_emit_subrequest = 0,
    fastcgi_read_header, //1
    fastcgi_read_header_content, //2
    fastcgi_read_data, //3
    fastcgi_send_data, //4
    fastcgi_not_found, //5
    fastcgi_expired //6
};

typedef struct {
    ngx_uint_t                  state;
    ngx_str_t                   cache_url;
    ngx_uint_t                  orig_method;
    ngx_str_t                   orig_method_name;
    ngx_chain_t                 *in;
} ngx_http_fastcgi_cache_priv_t;

typedef struct {
    ngx_str_t                   location;
    ngx_str_t                   zone;
} ngx_http_fastcgi_cache_conf_t;

void ngx_http_fastcgi_cache_init(ngx_http_cache_t *c, ngx_http_upstream_t *u);
ngx_int_t ngx_http_fastcgi_cache_new(ngx_http_request_t *r);
ngx_int_t ngx_http_fastcgi_cache_create(ngx_http_request_t *r);
void ngx_http_fastcgi_cache_create_key(ngx_http_request_t *r);
ngx_int_t ngx_http_fastcgi_cache_open(ngx_http_request_t *r);
void ngx_http_fastcgi_cache_set_header(ngx_http_request_t *r, u_char *buf);
void ngx_http_fastcgi_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
ngx_int_t ngx_http_fastcgi_cache_send(ngx_http_request_t *r);
void ngx_http_fastcgi_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
time_t ngx_http_fastcgi_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);

char *ngx_http_fastcgi_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/*char *ngx_http_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

char *ngx_http_cache_set_type_slot(ngx_conf_t *cf, ngx_command_t *cmd,
     void *conf);
*/

extern ngx_str_t  ngx_http_cache_status[];


#endif /* _NGX_HTTP_FASTCGI_CACHE_H_INCLUDED_ */
