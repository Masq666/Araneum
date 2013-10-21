AC_INIT([Araneum], [0.8.2], [araneum@koppin22.com], [araneum])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(foreign)

AC_DEFUN([AC_PTHREAD_FREEBSD],
	[AC_MSG_CHECKING([if we need -pthread for threads])
	AC_CACHE_VAL(ac_ldflag_pthread,
		[ac_save_LDFLAGS="$LDFLAGS"
		LDFLAGS="-pthread $LDFLAGS"
		AC_TRY_LINK([char pthread_create();],
		pthread_create();,
		eval "ac_ldflag_pthread=yes",
		eval "ac_ldflag_pthread=no"),
		LDFLAGS="$ac_save_LDFLAGS"])
	if eval "test \"`echo $ac_ldflag_pthread`\" = yes"; then
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile etc/araneum/httpd.conf doc/araneum.1 doc/php-fcgi.1 doc/cgi-wrapper.1])

AC_PROG_CC
AC_PROG_INSTALL

AC_HEADER_STDC
AC_SYS_LARGEFILE
AC_CHECK_HEADERS([crypt.h rpcsvc/crypt.h netinet/in.h netinet/tcp.h arpa/inet.h sys/time.h])
LIB_SOCKET_NSL

AC_ARG_ENABLE([cache],
	[AC_HELP_STRING([--disable-cache], [disable file caching])],
	[ac_cv_enable_cache=$enableval],
	[AC_CACHE_CHECK([for caching], ac_cv_enable_cache, ac_cv_enable_cache=yes)])
if test $ac_cv_enable_cache = yes ; then
	AC_DEFINE_UNQUOTED([HAVE_CACHE], 1, [Define to 1 if you want Araneum to cache files])
fi

AC_ARG_ENABLE([chroot],
	[AC_HELP_STRING([--enable-chroot], [enable chroot support])],
	[ac_cv_enable_chroot=$enableval],
	[AC_CACHE_CHECK([for CommandChannel], ac_cv_enable_chroot, ac_cv_enable_chroot=no)])
LIBGCC_S=
if test $ac_cv_enable_chroot = yes ; then
	AC_DEFINE_UNQUOTED([HAVE_CHROOT], 1, [Define to 1 if you want chroot support])
	LIBGCC_S=-lgcc_s
fi

AC_ARG_ENABLE([debug],
	[AC_HELP_STRING([--enable-debug], [enable debug info (for development only)])],
	[ac_cv_enable_debug=$enableval],
	[AC_CACHE_CHECK([for debug support], ac_cv_enable_debug, ac_cv_enable_debug=no)])
if test $ac_cv_enable_debug = yes ; then
	AC_DEFINE_UNQUOTED([DEBUG], 1, [Define to 1 if you want debug info])
fi

AC_ARG_ENABLE([ipv6],
	[AC_HELP_STRING([--disable-ipv6], [disable IPv6 support])],
	[ac_cv_enable_ipv6=$enableval],
	[AC_CACHE_CHECK([for IPv6 support], ac_cv_enable_ipv6, ac_cv_enable_ipv6=yes)])
if test $ac_cv_enable_ipv6 = yes ; then
	AC_DEFINE_UNQUOTED([HAVE_IPV6], 1, [Define to 1 if you want IPv6 support])
fi

AC_ARG_ENABLE([ssl],
	[AC_HELP_STRING([--disable-ssl], [disable SSL support])],
	[ac_cv_enable_ssl=$enableval],
	[AC_CACHE_CHECK([for ssl support], ac_cv_enable_ssl, ac_cv_enable_ssl=yes)])
LIBCRYPTO=
LIBSSL=
if test $ac_cv_enable_ssl = yes ; then
	AC_DEFINE_UNQUOTED([HAVE_SSL], 1, [Define to 1 if you want SSL support])
	AC_CHECK_LIB([crypto], [BIO_free], LIBCRYPTO=-lcrypto)
	AC_CHECK_LIB([ssl], [SSL_library_init], LIBSSL=-lssl, LIBSSL=, $LIBCRYPTO)
fi

AC_ARG_ENABLE([toolkit],
	[AC_HELP_STRING([--disable-toolkit], [disable URL toolkit])],
	[ac_cv_enable_toolkit=$enableval],
	[AC_CACHE_CHECK([for URL toolkit], ac_cv_enable_toolkit, ac_cv_enable_toolkit=yes)])
if test $ac_cv_enable_toolkit = yes ; then
	AC_DEFINE_UNQUOTED([HAVE_TOOLKIT], 1, [Define to 1 if you want to enable the URL toolkit])
fi



case "$build_os" in 
*cygwin*)
	AC_DEFINE_UNQUOTED([CYGWIN], 1, [Define to 1 if building on Cygwin])
	AC_DEFINE_UNQUOTED([CIFS], 1, [Define to 1 if building on case-insensitive filesystem])
	;;
darwin*)
	AC_DEFINE_UNQUOTED([CIFS], 1, [Define to 1 if building on case-insensitive filesystem])
	;;
esac

AC_SUBST(LIBCRYPTO)
AC_SUBST(LIBSSL)
AC_SUBST(LIBGCC_S)

AC_CHECK_FUNCS([clearenv])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([strcasestr])
AC_CHECK_FUNCS([setenv])
AC_CHECK_FUNCS([unsetenv])
AC_CHECK_FUNC([crypt])
AC_CHECK_FUNC([gzdopen])
AC_CHECK_LIB([crypt], [crypt], LIBCRYPT=-lcrypt, LIBCRYPT=)
AC_SUBST(LIBCRYPT)
AC_CHECK_LIB([z], [gzdopen], LIBZ=-lz, LIBZ=)
AC_SUBST(LIBZ)
AC_CHECK_LIB([network], [socket], LDFLAGS="${LDFLAGS} -lnetwork")
ACX_PTHREAD

test "x$prefix" = xNONE && prefix=$ac_default_prefix
eval pkgsysconfdir="${sysconfdir}/araneum"
AC_SUBST(pkgsysconfdir)

AC_ARG_VAR([webrootdir],[The webroot directory. If not specified ${localstatedir}/www/araneum is used])
if test "${webrootdir}" = "" ; then
	eval webrootdir="${localstatedir}/www/araneum"
fi
AC_SUBST(webrootdir)

eval logdir="${localstatedir}/log/araneum"
AC_SUBST(logdir)
eval pidfiledir="${localstatedir}/run"
AC_SUBST(pidfiledir)
eval workdir="${localstatedir}/lib/araneum"
AC_SUBST(workdir)

AC_DEFINE_UNQUOTED([CONFIG_DIR], "$pkgsysconfdir", [directory for configurationfiles])
AC_DEFINE_UNQUOTED([SBIN_DIR], "$sbindir", [directory for system binaries])
AC_DEFINE_UNQUOTED([WEBROOT_DIR], "$webrootdir", [webroot directory])
AC_DEFINE_UNQUOTED([LOG_DIR], "$logdir", [directory for logfiles])
AC_DEFINE_UNQUOTED([PIDFILE_DIR], "$pidfiledir", [directory for the pidfile])
AC_DEFINE_UNQUOTED([WORK_DIR], "$workdir", [work directory])

AC_DEFINE_UNQUOTED([_GNU_SOURCE], 1, [Necessary for getsid()])

AC_OUTPUT
