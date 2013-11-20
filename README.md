About
========

The implementation of the consistent hash algorithm.
Using this module, can quickly bulid applications based on consistent hash algorithm.


API
========

If you want to use this module, will invoke these APIs.

[ngx_http_conhash_test_module][] to show you how to use these APIs.

```bash

ngx_int_t 
ngx_conhash_node_traverse(ngx_conhash_t *conhash, ngx_conhash_oper_pt func, void *data);

ngx_int_t 
ngx_conhash_add_node(ngx_conhash_t *conhash, u_char *name, size_t len);

ngx_int_t 
ngx_conhash_del_node(ngx_conhash_t *conhash, u_char *name, size_t len);

ngx_conhash_vnode_t* 
ngx_conhash_lookup_node(ngx_conhash_t *conhash, u_char *key, size_t len);

char *
ngx_conhash_shm_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void 
ngx_conhash_destroy(ngx_conhash_t *conhash);

```

See also
========
* [ngx_http_conhash_test_module][]

[ngx_http_conhash_test_module]: https://github.com/agile6v/ngx_http_conhash_test_module

