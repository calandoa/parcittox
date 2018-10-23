##
## Copyright (C) 2004-2007 Free Software Foundation, Inc.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##

noinst_LIBRARIES = libdittox.a

libdittox_a_CXXFLAGS = -I win_compat -include win_compat.h -I ditto -I ditto/EncryptDecrypt

libdittox_a_SOURCES = dittox.cpp \
	ditto/EncryptDecrypt/Encryption.cpp \
	ditto/EncryptDecrypt/rijndael.cpp \
	ditto/EncryptDecrypt/NewRandom.cpp \
	ditto/EncryptDecrypt/sha2.cpp \
	ditto/EncryptDecrypt/MemUtil.cpp

libdittox_a_DEPENDENCIES = $(LIBOBJS)
libdittox_a_LIBADD = $(LIBOBJS)
