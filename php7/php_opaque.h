/* opaque extension for PHP */

#ifndef PHP_OPAQUE_H
# define PHP_OPAQUE_H

extern zend_module_entry opaque_module_entry;
# define phpext_opaque_ptr &opaque_module_entry

# define PHP_OPAQUE_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_OPAQUE)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_OPAQUE_H */
