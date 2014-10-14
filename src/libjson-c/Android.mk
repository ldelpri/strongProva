# This file is generated by androgenizer for:
# [x] NDK
# [ ] system

LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:=libjson-c

LOCAL_MODULE_TAGS:=eng debug 

LOCAL_SRC_FILES := \
	arraylist.c \
	debug.c \
	json_c_version.c \
	json_object.c \
	json_object_iterator.c \
	json_tokener.c \
	json_util.c \
	linkhash.c \
	printbuf.c \
	random_seed.c \
	arraylist.h \
	bits.h \
	debug.h \
	json.h \
	json_config.h \
	json_c_version.h \
	json_inttypes.h \
	json_object.h \
	json_object_iterator.h \
	json_object_private.h \
	json_tokener.h \
	json_util.h \
	linkhash.h \
	printbuf.h \
	random_seed.h


LOCAL_LDFLAGS:=\
	-Wl,-Bsymbolic-functions

LOCAL_CFLAGS := \
	-DHAVE_CONFIG_H

LOCAL_C_INCLUDES := \
    $(strongswan_PATH)/src/libjson-c

LOCAL_PRELINK_MODULE := false
LOCAL_ARM_MODE:=arm

include $(BUILD_SHARED_LIBRARY)