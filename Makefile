
#  Makefile for SPP. Based on Makefile for 'split' (Andre Rojas)
#
#  Targets:
#
#    <default>  : see target "all"
#    all        : build all source and binaries
#    clean      : clean up object files and binaries 
#
#  Amiel Heyde
#

NAME = spp
SRCDIR=./src

SOURCES.c=  $(SRCDIR)/crc32.c \
	    $(SRCDIR)/instance.c \
	    $(SRCDIR)/pair.c \
            $(SRCDIR)/record.c \
            $(SRCDIR)/spptool.c \
            $(SRCDIR)/timeval.c \
            $(SRCDIR)/master.c \
            $(SRCDIR)/slave.c \


INCLUDES =  $(SRCDIR)/crc32.h \
	    $(SRCDIR)/instance.h \
	    $(SRCDIR)/pair.h \
            $(SRCDIR)/record.h \
            $(SRCDIR)/spptool.h \
            $(SRCDIR)/timeval.h \
            $(SRCDIR)/master.h \
            $(SRCDIR)/slave.h \
            $(SRCDIR)/rtp.h \
            $(SRCDIR)/config.h

            

SLIBS=  -pthread -lpcap
BINDIR=./bin
PROGRAM= $(BINDIR)/$(NAME)
CFLAGS += -I/usr/local/include 
LDFLAGS += -L/usr/local/lib
INSTALL= install



# If, for some reason, you don't want debugging info to bewww
# logged, then comment the following line.
#
CFLAGS+= -DDEBUG

# If you want the program with support for debuggers
# (gdb, etc), then uncomment the following line
CFLAGS+= -g

# turn on optimisation
CFLAGS += -O2

# turn on warnings
CFLAGS += -Wall

OBJECTS= $(SOURCES.c:.c=.o)

# default target (or specify "make all" if you prefer)

all: $(PROGRAM)

.KEEP_STATE:


.c.o: $(INCLUDES)
	    $(CC) $(CFLAGS) -c $< -o $@

$(PROGRAM): $(OBJECTS)
	    $(CC) -o $@ $(OBJECTS) $(CFLAGS) $(LDFLAGS) $(SLIBS) 

clean:
	    rm -f $(PROGRAM) *.o $(SRCDIR)/*.o *~

install:
	@if test "`id -u`" != "0" ; then \
		echo "You must be root to install" && exit 1 ; \
	fi ;	
	@echo "Installing spp binary"
	$(INSTALL) -c -m 755 $(PROGRAM) /usr/local/bin/
	@echo "Installing manual page"
	$(INSTALL) -c -m 644 doc/spp.1 /usr/local/man/man1/	

# target 'distro'
#
# Tars and gzip's the distribtion - use for development
#
DISTRONAME=spp-0.3.6

distro:
#Make a gzip archive with only the necessary files
	mkdir $(DISTRONAME); cp -a * $(DISTRONAME); rm -rf $(DISTRONAME)/$(DISTRONAME); tar --exclude="*.svn*" --exclude="*.o" --exclude="*~" --exclude="*.old" --exclude="*.orig" --exclude="*.kde*" --exclude="*.out" --exclude="*.new" --exclude="*Doxyfile*" --exclude="*bin/spp*" --exclude="src-fork" --exclude="spp-*.tar.gz" --format=ustar -cvf ${DISTRONAME}.tar ${DISTRONAME}; rm -rf $(DISTRONAME); gzip $(DISTRONAME).tar; 




