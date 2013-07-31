# Copyright (C) 2013, Red Hat, Inc.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.

#   Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.

#   Neither the name of Red Hat, Inc., nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

CWARNS = --std=gnu99 -Wall -Wextra -pedantic
CDEBUG = -O3 # use for maximal warning checks
#CDEBUG = -O0 -ggdb # use for debugging

CFLAGS = $(shell pkg-config --cflags glib-2.0) $(CWARNS) $(CDEBUG)
LFLAGS = $(shell pkg-config --libs glib-2.0)

all: test

cside.o: cside.c cside.h
	gcc -c $(CFLAGS) -o cside.o cside.c

cside_full.o: cside.h cside_full.h cside_full.c
	gcc -c $(CFLAGS) -o cside_full.o cside_full.c

test: cside_full.o cside.o
	gcc $(LFLAGS) -o test cside_full.o cside.o

clean:
	rm -f a.out
	rm -f *.o
	rm -f *.gdb
	rm -f test
