/*
 * Copyright (C) agile6v
 */

#include <ngx_consistent_hash.h>

static ngx_int_t ngx_conhash_shm_init(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_conhash_add_replicas(ngx_conhash_t *conhash, ngx_conhash_node_t *hnode);
static ngx_int_t ngx_conhash_del_replicas(ngx_conhash_t *conhash, ngx_conhash_node_t *hnode, ngx_uint_t replicas);
static ngx_int_t ngx_conhash_make_vnode_name(ngx_conhash_t *conhash, ngx_str_t *name,
    ngx_conhash_node_t *hnode, ngx_uint_t index);
static void ngx_conhash_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_rbtree_node_t* ngx_conhash_rbtree_lookup(ngx_conhash_t *conhash, ngx_str_t *name,
    ngx_rbtree_key_t key);
static void ngx_conhash_tree_mid_traverse(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_conhash_oper_pt func, void *data);

void
ngx_conhash_clear(ngx_conhash_t *conhash)
{
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_conhash_vnode_t  *vnode;
    ngx_conhash_node_t   *hnode;
    ngx_queue_t          *q;
    
    if (conhash == NULL || conhash == NGX_CONF_UNSET_PTR) {
        return;
    }
    
    ngx_shmtx_lock(&conhash->shpool->mutex);
    
    if (ngx_queue_empty(&conhash->sh->hnode_queue)) {
        ngx_shmtx_unlock(&conhash->shpool->mutex);
        return;
    }
    
    for (q = ngx_queue_head(&conhash->sh->hnode_queue);
         q != ngx_queue_sentinel(&conhash->sh->hnode_queue);
         q = ngx_queue_next(q))
    {
        hnode = ngx_queue_data(q, ngx_conhash_node_t, queue);
        ngx_slab_free_locked(conhash->shpool, hnode->name.data);
        ngx_slab_free_locked(conhash->shpool, hnode);
        ngx_queue_remove(q);
    }
    
    sentinel = conhash->sh->vnode_tree.sentinel;
    
    while (conhash->sh->vnode_tree.root != sentinel) {
        
        node = conhash->sh->vnode_tree.root;
        
        vnode = (ngx_conhash_vnode_t *) node;
        
        ngx_rbtree_delete(&conhash->sh->vnode_tree, node);
        
        ngx_slab_free_locked(conhash->shpool, vnode->name.data);
        ngx_slab_free_locked(conhash->shpool, vnode);
        
        conhash->sh->vnodes--;
    }
    
    ngx_shmtx_unlock(&conhash->shpool->mutex);
}

ngx_int_t
ngx_conhash_add_node(ngx_conhash_t *conhash, u_char *name, size_t len, void *data)
{
    ngx_int_t               rc;
    ngx_queue_t            *q;
    ngx_conhash_node_t     *hnode;
    size_t                  size;
    
    if (conhash == NULL
        || conhash == NGX_CONF_UNSET_PTR
        || conhash->shpool == NULL 
        || conhash->sh == NULL)
    {
        return NGX_ERROR;
    }
    
    ngx_shmtx_lock(&conhash->shpool->mutex);
    
    for (q = ngx_queue_head(&conhash->sh->hnode_queue);
         q != ngx_queue_sentinel(&conhash->sh->hnode_queue);
         q = ngx_queue_next(q))
    {
        hnode = ngx_queue_data(q, ngx_conhash_node_t, queue);
        if (hnode) {
            rc = ngx_memn2cmp(hnode->name.data, name, hnode->name.len, len);
            if (rc == 0) {
                rc = NGX_DECLINED;
                goto done;
            }
        }
    }
    
    hnode = ngx_slab_alloc_locked(conhash->shpool, sizeof(ngx_conhash_node_t));
    if (hnode == NULL) {
        rc = NGX_ERROR;
        goto done;
    }
    
    size = (len < NGX_CONHASH_NAME_SIZE) ? len : NGX_CONHASH_NAME_SIZE - 1;
    
    hnode->name.len = size;
    hnode->name.data = ngx_slab_alloc_locked(conhash->shpool, size + 1);
    if (hnode->name.data == NULL) {
        ngx_slab_free_locked(conhash->shpool, hnode);
        rc = NGX_ERROR;
        goto done;
    }
    
    ngx_memcpy(hnode->name.data, name, size);
    hnode->name.data[size] = '\0';
    hnode->data = data;
    
    rc = ngx_conhash_add_replicas(conhash, hnode);
    if (rc != NGX_OK) {
        ngx_slab_free_locked(conhash->shpool, hnode->name.data);
        ngx_slab_free_locked(conhash->shpool, hnode);
        goto done;
    }
    
    ngx_queue_insert_tail(&conhash->sh->hnode_queue, &hnode->queue);

done:
    ngx_shmtx_unlock(&conhash->shpool->mutex);
    
    return rc;
}

ngx_int_t
ngx_conhash_del_node(ngx_conhash_t *conhash, u_char *name, size_t len)
{
    ngx_int_t               rc, ret;
    ngx_queue_t            *q;
    ngx_conhash_node_t     *hnode;
    
    if (conhash == NULL
        || conhash == NGX_CONF_UNSET_PTR
        || conhash->shpool == NULL
        || conhash->sh == NULL)
    {
        return NGX_ERROR;
    }
    
    rc = NGX_DECLINED;
    
    ngx_shmtx_lock(&conhash->shpool->mutex);
    
    for (q = ngx_queue_head(&conhash->sh->hnode_queue);
         q != ngx_queue_sentinel(&conhash->sh->hnode_queue);
         q = ngx_queue_next(q))
    {
        hnode = ngx_queue_data(q, ngx_conhash_node_t, queue);
        
        ret = ngx_memn2cmp(hnode->name.data, name, hnode->name.len, len);

        if (ret == 0) {
        
            rc = ngx_conhash_del_replicas(conhash, hnode, conhash->vnodecnt);
            if (rc != NGX_OK) {
                goto done;
            }
            
            ngx_slab_free_locked(conhash->shpool, hnode->name.data);
            ngx_slab_free_locked(conhash->shpool, hnode);
            ngx_queue_remove(q);
            break;
        }
    }

done:
    ngx_shmtx_unlock(&conhash->shpool->mutex);

    return rc;
}

ngx_int_t
ngx_conhash_lookup_node(ngx_conhash_t *conhash, u_char *name, size_t len, 
    ngx_conhash_oper_pt func, void *data)
{
    ngx_rbtree_key_t      node_key;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_conhash_vnode_t  *vnode;
    ngx_int_t             rc;
    
    vnode = NULL;
    node_key = conhash->hash_func(name, len);
    
    ngx_shmtx_lock(&conhash->shpool->mutex);
    
    node = conhash->sh->vnode_tree.root;
    sentinel = conhash->sh->vnode_tree.sentinel;
    
    if (node == sentinel) {
        rc = NGX_DECLINED;
        goto done;
    }
    
    while (node != sentinel) {
        
        if (node_key <= node->key) {
            vnode = (ngx_conhash_vnode_t *) node;
            node = node->left;
            continue;
        }
        
        if (node_key > node->key) {
            node = node->right;
            continue;
        }
    }
    
    if (vnode == NULL) {
        node = ngx_rbtree_min(conhash->sh->vnode_tree.root, sentinel);
        vnode = (ngx_conhash_vnode_t *) node;
    }
    
    func(vnode, data);
    
    rc = NGX_OK;

done:
    ngx_shmtx_unlock(&conhash->shpool->mutex);
    
    return rc;
}

static ngx_rbtree_node_t*
ngx_conhash_rbtree_lookup(ngx_conhash_t *conhash, ngx_str_t *name, ngx_rbtree_key_t key)
{
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_conhash_vnode_t  *vnode;
    ngx_int_t             rc;
    
    node = conhash->sh->vnode_tree.root;
    sentinel = conhash->sh->vnode_tree.sentinel;
        
    while (node != sentinel) {
    
        if (key < node->key) {
            node = node->left;
            continue;
        }
        
        if (key > node->key) {
            node = node->right;
            continue;
        }
        
        vnode = (ngx_conhash_vnode_t *) node;
        
        rc = ngx_memn2cmp(name->data, vnode->name.data, name->len, vnode->name.len);
        if (rc == 0) {
            return node;
        }
        
        node = (rc < 0) ? node->left : node->right;
    }
    
    return NULL;
}

static ngx_int_t 
ngx_conhash_add_replicas(ngx_conhash_t *conhash, ngx_conhash_node_t *hnode)
{
    ngx_uint_t               i;
    ngx_rbtree_key_t         key;
    ngx_str_t                vnode_name;
    ngx_conhash_vnode_t     *vnode;
    ngx_rbtree_node_t       *node;
    ngx_int_t                rc = NGX_OK;
    
    for (i = 0; i < conhash->vnodecnt; i++) {
        
        vnode_name.data = NULL;
        
        rc = ngx_conhash_make_vnode_name(conhash, &vnode_name, hnode, i);
        if (rc == NGX_ERROR) {
            goto done;
        }
        
        key = conhash->hash_func(vnode_name.data, vnode_name.len);

        node = ngx_conhash_rbtree_lookup(conhash, &vnode_name, key);
        if (node != NULL) {
            ngx_slab_free_locked(conhash->shpool, vnode_name.data);
            continue;
        }
        
        vnode = ngx_slab_alloc_locked(conhash->shpool,
                                      sizeof(ngx_conhash_vnode_t));
        if (vnode == NULL) {
            ngx_slab_free_locked(conhash->shpool, vnode_name.data);
            rc = NGX_ERROR;
            goto done;
        }
        
        vnode->node.key = key;
        vnode->hnode = hnode;
        vnode->name = vnode_name;

        ngx_rbtree_insert(&conhash->sh->vnode_tree, &vnode->node);
        conhash->sh->vnodes++;
    }

done:

    if (rc != NGX_OK && i < conhash->vnodecnt) {
        
        rc = ngx_conhash_del_replicas(conhash, hnode, i);
        if (rc != NGX_OK) {
            return rc;
        }
        
        return NGX_AGAIN;
    }
    
    return NGX_OK;
}

static ngx_int_t 
ngx_conhash_del_replicas(ngx_conhash_t *conhash, ngx_conhash_node_t *hnode, ngx_uint_t replicas)
{
    ngx_uint_t           i;
    ngx_int_t            rc;
    ngx_rbtree_key_t     key;
    ngx_str_t            vnode_name;
    u_char               name[1024];
    ngx_conhash_vnode_t *vnode;
    ngx_rbtree_node_t   *node;
    
    for (i = 0; i < replicas; i++) {
        
        ngx_memzero(name, sizeof(name));
        
        vnode_name.data = name;
        
        rc = ngx_conhash_make_vnode_name(conhash, &vnode_name, hnode, i);
        if (rc == NGX_ERROR) {
            return rc;
        }
        
        key = conhash->hash_func(vnode_name.data, vnode_name.len);

        node = ngx_conhash_rbtree_lookup(conhash, &vnode_name, key);
        if (node == NULL) {
            continue;
        }
        
        vnode = (ngx_conhash_vnode_t *) node;
        
        ngx_rbtree_delete(&conhash->sh->vnode_tree, node);
        ngx_slab_free_locked(conhash->shpool, vnode->name.data);
        ngx_slab_free_locked(conhash->shpool, vnode);
        
        conhash->sh->vnodes--;
    }
    
    return NGX_OK;
}

static ngx_int_t 
ngx_conhash_make_vnode_name(ngx_conhash_t *conhash, ngx_str_t *name,
    ngx_conhash_node_t *hnode, ngx_uint_t index)
{
    u_char      *p;
    
    name->len = hnode->name.len + 5;
    
    if (name->data == NULL) {
        name->data = ngx_slab_alloc_locked(conhash->shpool, name->len + 1);
        if (name->data == NULL) {
            return NGX_ERROR;
        }
    }
    
    p = name->data;
    p = ngx_sprintf(p, "%V-%04ui", &hnode->name, index);
    *p++ = '\0';

    return NGX_OK;
}

static void
ngx_conhash_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_conhash_vnode_t   *vnode, *vnode_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else {

            vnode = (ngx_conhash_vnode_t *) node;
            vnode_temp = (ngx_conhash_vnode_t *) temp;

            p = (ngx_memn2cmp(vnode->name.data, vnode_temp->name.data, vnode->name.len, 
                              vnode_temp->name.len) < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

char *
ngx_conhash_shm_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;
    
    ssize_t                 size;
    ngx_str_t               name, *value, s;
    ngx_conhash_t          *conhash, **conhash_p;
    ngx_conhash_ctx_t      *conhash_ctx;
    ngx_int_t               vnode_cnt;
    u_char                 *ptr;
    
    conhash_p = (ngx_conhash_t **) (p + cmd->offset);
    
    if (*conhash_p != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }
    
    vnode_cnt = 100;
    value = cf->args->elts;
    
    if (ngx_strncmp(value[1].data, "keys_zone=", 10) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    
    name.data = value[1].data + 10;
    
    ptr = (u_char *) ngx_strchr(name.data, ':');
    if (!ptr) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    
    name.len = ptr - name.data;
    ptr++;
    
    s.len = value[1].data + value[1].len - ptr;
    s.data = ptr;

    size = ngx_parse_size(&s);

    if (size < (ngx_int_t) (2 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid keys zone size \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    
    if (cf->args->nelts > 2) {
        if (ngx_strncmp(value[2].data, "vnodecnt=", 9) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        
        s.len = value[2].len - 9;
        s.data = value[2].data + 9;
        
        vnode_cnt = ngx_atoi(s.data, s.len);
        if (vnode_cnt == NGX_ERROR || vnode_cnt > 10000) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid vnode count \"%V\", is not greater than 10000", &value[2]);
            return NGX_CONF_ERROR;
        }
    }
    
    conhash = (ngx_conhash_t *) ngx_pcalloc(cf->pool, sizeof(ngx_conhash_t));
    if (conhash == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conhash_ctx = (ngx_conhash_ctx_t *) cmd->post;
    if (conhash_ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    
    if (conhash_ctx->hash_func != NULL) {
        conhash->hash_func = conhash_ctx->hash_func;
    } else {
        conhash->hash_func = ngx_murmur_hash2;
    }
    
    conhash->shm_zone = ngx_shared_memory_add(cf, &name, size, conhash_ctx->data);
    if (conhash->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (conhash->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }
    
    conhash->shm_zone->init = ngx_conhash_shm_init;
    conhash->shm_zone->data = conhash;
    conhash->vnodecnt = vnode_cnt;
    
    *conhash_p = conhash;
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_conhash_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_conhash_t   *o_conhash = data;
    
    ngx_conhash_t   *conhash;
    size_t           len;

    conhash = shm_zone->data;
    
    if (o_conhash) {
        conhash->sh = o_conhash->sh;
        conhash->shpool = o_conhash->shpool;
        return NGX_OK;
    }
    
    conhash->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    
    conhash->sh = ngx_slab_alloc(conhash->shpool, sizeof(ngx_conhash_sh_t));
    if (conhash->sh == NULL) {
        return NGX_ERROR;
    }
    
    conhash->shpool->data = conhash->sh;

    ngx_rbtree_init(&conhash->sh->vnode_tree, &conhash->sh->vnode_sentinel,
                    ngx_conhash_rbtree_insert_value);
                    
    ngx_queue_init(&conhash->sh->hnode_queue);
    
    len = sizeof(" in conhash zone \"\"") + shm_zone->shm.name.len;

    conhash->shpool->log_ctx = ngx_slab_alloc(conhash->shpool, len);
    if (conhash->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(conhash->shpool->log_ctx, " in conhash zone \"%V\"%Z",
                &shm_zone->shm.name);
    
    return NGX_OK;
}

ngx_int_t
ngx_conhash_node_traverse(ngx_conhash_t *conhash, ngx_conhash_oper_pt func, void *data)
{
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_int_t             rc;

    rc = NGX_OK;
    
    ngx_shmtx_lock(&conhash->shpool->mutex);

    node = conhash->sh->vnode_tree.root;
    sentinel = conhash->sh->vnode_tree.sentinel;
    
    if (node == sentinel) {
        rc = NGX_DECLINED;
        goto done;
    }
    
    ngx_conhash_tree_mid_traverse(node, sentinel, func, data);

done:

    ngx_shmtx_unlock(&conhash->shpool->mutex);
    
    return rc;
}

static void
ngx_conhash_tree_mid_traverse(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, 
    ngx_conhash_oper_pt func, void *data)
{
    ngx_conhash_vnode_t  *vnode;
    
    if (node->left != sentinel) {
        ngx_conhash_tree_mid_traverse(node->left, sentinel, func, data);
    }
    
    vnode = (ngx_conhash_vnode_t *) node;
    
    func(vnode, data);
    
    if (node->right != sentinel) {
        ngx_conhash_tree_mid_traverse(node->right, sentinel, func, data);
    }
}

