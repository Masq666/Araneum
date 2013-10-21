ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = ssi-cgi
sbin_PROGRAMS = cgi-wrapper araneum php-fcgi wigwam
sbin_SCRIPTS = extra/newroot

cgi_wrapper_SOURCES = \
	alternative.c \
	alternative.h \
	cgi-wrapper.c \
	userconfig.c \
	userconfig.h \
	libfs.c \
	libfs.h \
	libstr.c \
	libstr.h

araneum_SOURCES = \
	alternative.c \
	alternative.h \
	cache.c \
	cache.h \
	cgi.c \
	cgi.h \
	client.c \
	client.h \
	envir.c \
	envir.h \
	global.h \
	araneum.c \
	httpauth.c \
	httpauth.h \
	libfs.c \
	libfs.h \
	libip.c \
	libip.h \
	liblist.c \
	liblist.h \
	libmd5.c \
	libmd5.h \
	libstr.c \
	libstr.h \
	libssl.c \
	libssl.h \
	log.c \
	log.h \
	mimetype.c \
	mimetype.h \
	send.c \
	send.h \
	serverconfig.c \
	serverconfig.h \
	session.c \
	session.h \
	target.c \
	target.h \
	toolkit.c \
	toolkit.h \
	userconfig.c \
	userconfig.h
araneum_CFLAGS = $(PTHREAD_CFLAGS) $(XML_CFLAGS)
araneum_LDADD = $(PTHREAD_LIBS) $(LIBCRYPT) $(LIBSSL) $(LIBCRYPTO) $(LIBXML) $(LIBZ) $(LIBGCC_S)

php_fcgi_SOURCES = \
	alternative.c \
	alternative.h \
	libip.c \
	libip.h \
	liblist.c \
	liblist.h \
	libstr.c \
	libstr.h \
	php-fcgi.c \
	userconfig.c \
	userconfig.h

ssi_cgi_SOURCES = \
	alternative.c \
	alternative.h \
	libip.c \
	libip.h \
	liblist.c \
	liblist.h \
	libstr.c \
	libstr.h \
	ssi-cgi.c

wigwam_SOURCES = \
	alternative.c \
	alternative.h \
	libfs.c \
	libfs.h \
	libstr.c \
	libstr.h \
	toolkit.c \
	toolkit.h \
	wigwam.c

configurefiles = \
	etc/araneum/cgi-wrapper.conf \
	etc/araneum/httpd.conf \
	etc/araneum/mimetype.conf \
	etc/araneum/php-fcgi.conf

install-data-hook:
	@if [ ! -d $(localstatedir)/run ] ; then \
		mkdir -p $(localstatedir)/run ; \
	fi
	@for file in $(configurefiles) ; do \
		inst=$(DESTDIR)$(pkgsysconfdir)/`echo $${file} | sed -e 's/^.*\///'`; \
		test -f $${inst} || $(install_sh_DATA) $(srcdir)/$${file} $${inst} ; \
	done

uninstall-hook:
	@if [ -e $(localstatedir)/run/araneum.pid ] ; then \
		rm $(localstatedir)/run/araneum.pid ; \
	fi
	@for file in $(configurefiles) ; do \
		inst=$(DESTDIR)$(pkgsysconfdir)/`echo $${file} | sed -e 's/^.*\///'`; \
		rm -f $${inst} ; \
	done

webroot_DATA = \
	doc/index.html \
	doc/araneum_logo.png

log_DATA =

man1_MANS = \
	doc/cgi-wrapper.1 \
	doc/araneum.1 \
	doc/newroot.1 \
	doc/php-fcgi.1 \
	doc/ssi-cgi.1 \
	doc/wigwam.1

EXTRA_DIST = \
	$(man1_MANS) \
	$(webroot_DATA) \
	$(configurefiles) \
	etc/logrotate.d/araneum \
	debian/README.debian \
	debian/compat \
	debian/conffiles \
	debian/control \
	debian/copyright \
	debian/araneum.dirs \
	debian/araneum.postinst \
	debian/araneum.postrm \
	debian/info \
	debian/init.d \
	debian/rules \
	doc/sourcecode.txt \
	extra/cygwin_config.h \
	extra/araneum \
	extra/mkcert \
	extra/newroot \
	extra/php-fcgi

install-exec-hook:
	chmod u+s $(DESTDIR)$(sbindir)/`echo cgi-wrapper | sed -e "$(program_transform_name)"`

deb:
	cp -f ChangeLog debian/changelog
	dpkg-buildpackage -rfakeroot

win:
	cp extra/cygwin_config.h config.h
	make
	strip *.exe
	
haiku:
	./configure --disable-ssl --disable-xslt --prefix=/boot/home/araneum
	make && make install
crt:
	extra/mkcert
	
pdf:
	man -t doc/araneum.1 | ps2pdf -> araneum.pdf
	man -t doc/cgi-wrapper.1 | ps2pdf -> cgi-wrapper.pdf
	man -t doc/newroot.1 | ps2pdf -> newroot.pdf
	man -t doc/php-fcgi.1 | ps2pdf -> php-fcgi.pdf
	man -t doc/ssi-cgi.1 | ps2pdf -> ssi-cgi.pdf
	man -t doc/wigwam.1 | ps2pdf -> wigwam.pdf
	
html:
	man2html doc/araneum.1 > araneum.html
	man2html doc/cgi-wrapper.1 > cgi-wrapper.html
	man2html doc/newroot.1 > newroot.html
	man2html doc/php-fcgi.1 > php-fcgi.html
	man2html doc/ssi-cgi.1 > ssi-cgi.html
	man2html doc/wigwam.1 > wigwam.html
	
