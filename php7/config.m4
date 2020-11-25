dnl config.m4 for extension opaque

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary.

dnl If your extension references something external, use 'with':

PHP_ARG_WITH([opaque],
  [for opaque support],
  [AS_HELP_STRING([--with-opaque],
    [Include opaque support])])

dnl Otherwise use 'enable':

dnl PHP_ARG_ENABLE([opaque],
dnl   [whether to enable opaque support],
dnl   [AS_HELP_STRING([--enable-opaque],
dnl     [Enable opaque support])],
dnl   [no])

if test "$PHP_OPAQUE" != "no"; then
  dnl Write more examples of tests here...

  dnl Remove this code block if the library does not support pkg-config.
  PKG_CHECK_MODULES([LIBOPAQUE], [libopaque])
  PHP_EVAL_INCLINE($LIBOPAQUE_CFLAGS)
  PHP_EVAL_LIBLINE($LIBOPAQUE_LIBS, OPAQUE_SHARED_LIBADD)

  dnl If you need to check for a particular library version using PKG_CHECK_MODULES,
  dnl you can use comparison operators. For example:
  dnl PKG_CHECK_MODULES([LIBFOO], [foo >= 1.2.3])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo < 3.4])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo = 1.2.3])

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-opaque -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/opaque.h"  # you most likely want to change this
  dnl if test -r $PHP_OPAQUE/$SEARCH_FOR; then # path given as parameter
  dnl   OPAQUE_DIR=$PHP_OPAQUE
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for opaque files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       OPAQUE_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$OPAQUE_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the opaque distribution])
  dnl fi

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-opaque -> add include path
  dnl PHP_ADD_INCLUDE($OPAQUE_DIR/include)

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-opaque -> check for lib and symbol presence
  dnl LIBNAME=libopaque # you may want to change this
  dnl LIBSYMBOL=OPAQUE # you most likely want to change this

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   AC_DEFINE(HAVE_OPAQUE_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your opaque library.])
  dnl ], [
  dnl   $LIBFOO_LIBS
  dnl ])

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are not using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $OPAQUE_DIR/$PHP_LIBDIR, OPAQUE_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_OPAQUE_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your opaque library.])
  dnl ],[
  dnl   -L$OPAQUE_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  PHP_SUBST(OPAQUE_SHARED_LIBADD)

  dnl In case of no dependencies
  AC_DEFINE(HAVE_OPAQUE, 1, [ Have opaque support ])

  PHP_NEW_EXTENSION(opaque, opaque.c, $ext_shared)
fi
