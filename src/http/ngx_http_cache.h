
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_file_cache.h>
#include <ngx_http_fastcgi_cache.h>


#define NGX_HTTP_CACHE_MISS          1
#define NGX_HTTP_CACHE_BYPASS        2
#define NGX_HTTP_CACHE_EXPIRED       3
#define NGX_HTTP_CACHE_STALE         4
#define NGX_HTTP_CACHE_UPDATING      5
#define NGX_HTTP_CACHE_HIT           6
#define NGX_HTTP_CACHE_SCARCE        7

#define NGX_HTTP_CACHE_TYPE_FILE     0
#define NGX_HTTP_CACHE_TYPE_FASTCGI  1

#define NGX_HTTP_CACHE_KEY_LEN       16


typedef struct {
    ngx_uint_t                       status;
    time_t                           valid;
} ngx_http_cache_valid_t;


struct ngx_http_cache_s {
    ngx_file_t                       file;
    ngx_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];

    ngx_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;

    size_t                           header_start;
    size_t                           body_start;
    off_t                            length;
    off_t                            fs_size;

    ngx_uint_t                       min_uses;
    ngx_uint_t                       error;
    ngx_uint_t                       valid_msec;

    ngx_buf_t                       *buf;

    ngx_event_pipe_output_filter_pt  output_filter;
    void                            *output_ctx;

    void                            *cache_priv;

    unsigned                         updated:1;
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
};


void ngx_http_cache_init(ngx_http_cache_t *c, ngx_http_upstream_t *u);
ngx_int_t ngx_http_cache_new(ngx_http_request_t *r, ngx_http_upstream_t *u);
ngx_int_t ngx_http_cache_create(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_http_cache_create_key(ngx_http_request_t *r, ngx_http_upstream_t *u);
ngx_int_t ngx_http_cache_open(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_http_cache_set_header(ngx_http_request_t *r, u_char *buf, ngx_http_upstream_t *u);
void ngx_http_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf, ngx_http_upstream_t *u);
ngx_int_t ngx_http_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_http_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf, ngx_http_upstream_t *u);
time_t ngx_http_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status, ngx_http_upstream_t *u);

char *ngx_http_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

char *ngx_http_cache_set_type_slot(ngx_conf_t *cf, ngx_command_t *cmd,
     void *conf);


extern ngx_str_t  ngx_http_cache_status[];


#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
