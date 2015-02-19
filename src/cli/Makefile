APP       = cli

CC      := $gcc
AS      := $as
AR      := $ar
LD      := $ld

CFLAGS    += -g -O0 -fomit-frame-pointer -pipe -Wall -MD -MP

LDFLAGS   = -lm -lpthread -lrt

SRCDIR    = .
OBJDIR    = obj
LIBS      = 

INCLUDES  = 

SRCS    := $(shell find $(SRCDIR) -name '*.c')
SRCDIRS := $(shell find . -name '*.c' -exec dirname {} \; | uniq)
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

all: buildrepo $(APP)

$(APP): $(OBJS) $(LIBS)
	$(CC) $(LIBS) $(OBJS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR)
	find . -type l | xargs rm -f
	rm -f $(APP)

buildrepo:
	@for dir in $(SRCDIRS); do \
		mkdir -p $(OBJDIR)/$$dir; \
	done
