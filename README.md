ngx_consistent_hash
========

The implementation of the consistent hashing algorithm.

This Module(also a library) is based on Nginx's shared memory and red-black tree. If your application(or module) needs to use a consistent hashing algorithm(You need to know what problem it solves.) and work among worker processes at the same time, then this module is perfect for you.

**Performance**: Anyone who has used the Nginx proxy cache knows that the metadata of the cache is stored using shared memory and is synchronized using lock among worker processes. If you can accept the performance of the proxy cache, then you can accept it as well.

API
========

This module provieds the following APIs.

[ngx_http_conhash_test_module][] module can help you better understand how to use these APIs.

```bash

// This api uses the inorder traversal to traverse the entire red-black tree.
// Please use cauation if the number of nodes is large.
ngx_int_t 
ngx_conhash_node_traverse(ngx_conhash_t *conhash, ngx_conhash_oper_pt func, void *data);

ngx_int_t 
ngx_conhash_add_node(ngx_conhash_t *conhash, u_char *name, size_t len, void *data);

ngx_int_t 
ngx_conhash_del_node(ngx_conhash_t *conhash, u_char *name, size_t len);

ngx_int_t 
ngx_conhash_lookup_node(ngx_conhash_t *conhash, u_char *name, size_t len,
    ngx_conhash_oper_pt func, void *data);

void 
ngx_conhash_clear(ngx_conhash_t *conhash);

char *
ngx_conhash_shm_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

```

See also
========
* [ngx_http_conhash_test_module][]

[ngx_http_conhash_test_module]: https://github.com/agile6v/ngx_http_conhash_test_module

