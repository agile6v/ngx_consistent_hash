/*
 * Copyright (C) agile6v
 */

#ifndef _NGX_CONSISTENT_HASH_H_INCLUDED_
#define _NGX_CONSISTENT_HASH_H_INCLUDED_

#include <ngx_http.h>

#define NGX_CONHASH_NAME_SIZE   64

typedef struct ngx_conhash_vnode_s ngx_conhash_vnode_t;

typedef uint32_t (*ngx_conhash_hashfunc_pt) (u_char *data, size_t len);
typedef void (*ngx_conhash_oper_pt) (ngx_conhash_vnode_t *, void *);

typedef struct {
    ngx_conhash_hashfunc_pt     hash_func;
    void                       *data;
} ngx_conhash_ctx_t;

typedef struct {
    ngx_rbtree_t                vnode_tree;
    ngx_rbtree_node_t           vnode_sentinel;
    ngx_queue_t                 hnode_queue;
    ngx_uint_t                  vnodes;
} ngx_conhash_sh_t;

typedef struct {
    ngx_conhash_sh_t           *sh;
    ngx_slab_pool_t            *shpool;
    ngx_conhash_hashfunc_pt     hash_func;
    ngx_shm_zone_t             *shm_zone;
    ngx_uint_t                  vnodecnt;
} ngx_conhash_t;

typedef struct {
    u_char                  name[NGX_CONHASH_NAME_SIZE];
    ngx_queue_t             queue;
    void                   *data;
} ngx_conhash_node_t;

struct ngx_conhash_vnode_s {
    ngx_rbtree_node_t       node;
    ngx_conhash_node_t     *hnode;
    ngx_str_t               name;
} ;

ngx_int_t ngx_conhash_node_traverse(ngx_conhash_t *conhash, ngx_conhash_oper_pt func, void *data);
ngx_int_t ngx_conhash_add_node(ngx_conhash_t *conhash, u_char *name, size_t len, void *data);
ngx_int_t ngx_conhash_del_node(ngx_conhash_t *conhash, u_char *name, size_t len);
ngx_conhash_vnode_t* ngx_conhash_lookup_node(ngx_conhash_t *conhash, u_char *name, size_t len);
char *ngx_conhash_shm_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void ngx_conhash_clear(ngx_conhash_t *conhash);

#endif
