# ============================================================
# makefile v1
# url: https://github.com/aaiaia/make_c/tree/main/v1
# ============================================================
# default C language make environment
CC = gcc
CFLAGS = -fPIC -DTEST_AES -DTEST_SHA -DTEST_HMAC			# gcc compile flags, when use compile and linking
#CFLAGS = -fPIC -DTEST_AES -DTEST_SHA -DTEST_HMAC -DDEBUG	# gcc compile flags, when use compile and linking
# default C++ language make environment
CXX = g++
CXXFLAGS =		# g++ compile flags
CPPFLAGS =		# c++ compile flags
# default shared library environments
LDFLAGS = -lm	# linker flags
# default other make environment
AR = ar         # Static Library Archiving tools. The GNU ar program creates, modifies, and extracts from archives.
# define Shell command to make variable
RANLIB = ranlib # ranlib generates an index to the contents of an archive and stores it in the archive.
RM = rm
MV = mv
MKDIR = mkdir
MAKE = make
LN = ln

#ifeq ($(IS_SHARED),1)
# Some gcc based compiler to needs this option to fast executint program when use shared library.
$(info ###########################)
$(info ###### Compile Flags ######)
$(info ###########################)
#CFLAGS += -fPIC
$(info CFLAGS = ${CFLAGS})
#else
#endif

#ifeq ($(IS_SHARED),1)
$(info ###########################)
$(info ###### Linker Flags #*#####)
$(info ###########################)
#LDFLAGS += -lm
$(info LDFLAGS = ${LDFLAGS})
#else
#endif

$(info ###########################)
$(info ###### Configuration ######)
$(info ###########################)
$(info ###### Library Conf. ######)
MAJOR_VERSION = 1# 1
MINOR_VERSION = 0# 0

$(info #### Depend file prefix ###)
DEPEND_FILE_PREFIX = depend_file
$(info DEPEND_FILE_PREFIX = ${DEPEND_FILE_PREFIX})

$(info ###########################)
$(info ##### Release Version #####)
$(info ###########################)
OBJS_DIR_NAME = debug
$(info OBJS_DIR_NAME = ${OBJS_DIR_NAME})
$(info ###########################)
$(info ### Library Srcs & Objs ###)
$(info ###########################)
LIB_SRC_DIR_NAME = lib
$(info LIB_SRC_DIR_NAME = ${LIB_SRC_DIR_NAME})

LIB_SRCS := $(subst ./,,$(shell find -L ./$(LIB_SRC_DIR_NAME) -type f \( -iname "*.c" -o -iname "*.s" \) ))
$(info LIB_SRCS = ${LIB_SRCS})
#LIB_ITEMS = $(patsubst %.c,%,$(subst $(LIB_SRC_DIR_NAME)/,,$(LIB_SRCS)))
LIB_ITEMS = $(patsubst %.c,%,$(LIB_SRCS))
$(info LIB_ITEMS = ${LIB_ITEMS})
#LIB_OBJS := $(patsubst %.c,%.o,$(subst $(LIB_SRC_DIR_NAME),$(OBJS_DIR_NAME),$(LIB_SRCS)))
LIB_OBJS := $(LIB_SRCS:%.c=$(OBJS_DIR_NAME)/%.o)
$(info LIB_OBJS = ${LIB_OBJS})

LIB_INC_DIRS = -I${LIB_SRC_DIR_NAME}/include
$(info LIB_INC_DIRS = ${LIB_INC_DIRS})

DEPEND_FILE_POSTFIX_LIB = lib
$(info DEPEND_FILE_POSTFIX_LIB = ${DEPEND_FILE_POSTFIX_LIB})
DEPEND_FILE_LIB_SUFFIX = .$(DEPEND_FILE_POSTFIX_LIB)
DEPEND_FILE_LIB = $(OBJS_DIR_NAME)/$(DEPEND_FILE_PREFIX)$(DEPEND_FILE_LIB_SUFFIX)
$(info DEPEND_FILE_LIB = ${DEPEND_FILE_LIB})
$(info ###########################)
$(info ##### Library Config ######)
$(info ###########################)
LIB_NAME = alu
$(info LIB_NAME = ${LIB_NAME})
LIB_DIR_NAME = lib
$(info LIB_DIR_NAME = ${LIB_DIR_NAME})

COMMON_LIB_NAME = lib$(LIB_NAME)
$(info # Set variable to static library)
STATIC_LIB_KEYWD = static
$(info STATIC_LIB_KEYWD = ${STATIC_LIB_KEYWD})
STATIC_LIB_SUFFIX = .a
$(info STATIC_LIB_SUFFIX = ${STATIC_LIB_SUFFIX})
STATIC_LIB_NAME = $(COMMON_LIB_NAME)$(STATIC_LIB_SUFFIX)
$(info STATIC_LIB_NAME = ${STATIC_LIB_NAME})

$(info # Set variable to shared library)
SHARED_LIB_KEYWD = shared
$(info SHARED_LIB_KEYWD = ${SHARED_LIB_KEYWD})
SHARED_FLAGS = -fPIC
$(info SHARED_FLAGS = ${SHARED_FLAGS})
SHARED_LIB_SUFFIX = .so
$(info SHARED_LIB_SUFFIX = ${SHARED_LIB_SUFFIX})
SHARED_LIB_NAME = $(COMMON_LIB_NAME)$(SHARED_LIB_SUFFIX)
$(info SHARED_LIB_NAME = ${SHARED_LIB_NAME})
SHARED_LIB_NAME_VER_SUFFIX = .$(MAJOR_VERSION).$(MINOR_VERSION)
$(info SHARED_LIB_NAME_VER_SUFFIX = ${SHARED_LIB_NAME_VER_SUFFIX})
SHARED_LIB_NAME_VER = $(SHARED_LIB_NAME)$(SHARED_LIB_NAME_VER_SUFFIX)
$(info SHARED_LIB_NAME_VER = ${SHARED_LIB_NAME_VER})

$(info ###########################)
$(info ##### App Srcs & Objs #####)
$(info ###########################)
APP_SRC_DIR_NAME = app
$(info APP_SRC_DIR_NAME = ${APP_SRC_DIR_NAME})

APP_SRCS := $(subst ./,,$(shell find -L ./$(APP_SRC_DIR_NAME) -type f \( -iname "*.c" -o -iname "*.s" \) ))
$(info APP_SRCS = ${APP_SRCS})
#APP_ITEMS = $(patsubst %.c,%,$(subst $(APP_SRC_DIR_NAME)/,,$(APP_SRCS)))
APP_ITEMS = $(patsubst %.c,%,$(APP_SRCS))
$(info APP_ITEMS = ${APP_ITEMS})
#APP_OBJS := $(patsubst %.c,%.o,$(subst $(APP_SRC_DIR_NAME),$(OBJS_DIR_NAME),$(APP_SRCS)))
APP_OBJS := $(APP_SRCS:%.c=$(OBJS_DIR_NAME)/%.o)
$(info APP_OBJS = ${APP_OBJS})

APP_INC_DIRS = -I$(APP_SRC_DIR_NAME) $(LIB_INC_DIRS)
$(info APP_INC_DIRS = ${APP_INC_DIRS})

DEPEND_FILE_POSTFIX_APP = app
$(info DEPEND_FILE_POSTFIX_APP = ${DEPEND_FILE_POSTFIX_APP})
DEPEND_FILE_APP_SUFFIX = .$(DEPEND_FILE_POSTFIX_APP)
DEPEND_FILE_APP = $(OBJS_DIR_NAME)/$(DEPEND_FILE_PREFIX)$(DEPEND_FILE_APP_SUFFIX)
$(info DEPEND_FILE_APP = ${DEPEND_FILE_APP})
$(info ###########################)
$(info ### Application Config ####)
$(info ###########################)
# blank = compile using object
# static = compile use static library
# shared = compile use shared library
APP_USE_LIB_MODE =
$(info APP_USE_LIB_MODE = ${APP_USE_LIB_MODE})
$(info ###########################)
$(info #### Outputs & Target #####)
$(info ###########################)
OUT_DIR_NAME = out
$(info OUT_DIR_NAME = ${OUT_DIR_NAME})
$(info ##### Config for Lib #####)
OUT_LIB_DIR = $(OUT_DIR_NAME)/$(OBJS_DIR_NAME)/$(LIB_DIR_NAME)
$(info OUT_LIB_DIR = $(OUT_LIB_DIR))
OUT_LIB_PATH_STATIC = $(OUT_LIB_DIR)/$(STATIC_LIB_NAME)
$(info OUT_LIB_PATH_STATIC = $(OUT_LIB_PATH_STATIC))
OUT_LIB_PATH_SHARED = $(OUT_LIB_DIR)/$(SHARED_LIB_NAME)
$(info OUT_LIB_PATH_SHARED = $(OUT_LIB_PATH_SHARED))
OUT_LIB_PATH_SHARED_VER = $(OUT_LIB_DIR)/$(SHARED_LIB_NAME_VER)
$(info OUT_LIB_PATH_SHARED_VER = $(OUT_LIB_PATH_SHARED_VER))
OUT_LIB_PATH_COMMON = $(OUT_LIB_DIR)/$(COMMON_LIB_NAME)
$(info ##### Config for App #####)
OUT_ITEMS_APP = $(APP_OBJS:%.o=%)
$(info OUT_ITEMS_APP = $(OUT_ITEMS_APP))
OUT_APP = $(OUT_ITEMS_APP:%=$(OUT_DIR_NAME)/%)
$(info OUT_APP = ${OUT_APP})
$(info ###########################)
$(info #### Include to Library####)
$(info ###########################)
INC_LIB_PATH = -L$(OUT_LIB_DIR)
$(info INC_LIB_PATH = $(INC_LIB_PATH))

INC_LIB_NAMES = -l$(patsubst lib%.a,%,$(LIB_NAME))
$(info INC_LIB_NAMES = $(INC_LIB_NAMES))
$(info ###########################)
$(info ###########################)
$(info ###########################)

#.SUFFIXES : .c .o

###########################
###########################
###########################
test.test :
ifeq ($(APP_USE_LIB_MODE),)
	@echo "APP_USE_LIB_MODE: blank"
else ifeq ($(APP_USE_LIB_MODE),static)
	@echo "APP_USE_LIB_MODE: $(APP_USE_LIB_MODE)"
else ifeq ($(APP_USE_LIB_MODE),shared)
	@echo "APP_USE_LIB_MODE: $(APP_USE_LIB_MODE)"
else
	@echo "APP_USE_LIB_MODE: unknown"
endif
	@echo "$(suffix $(DEPEND_FILE_LIB))"
	@echo "$(suffix $(DEPEND_FILE_APP))"
ifeq ($(suffix $(DEPEND_FILE_LIB)),.$(DEPEND_FILE_POSTFIX_LIB))
	@echo "ifeq($(suffix $(DEPEND_FILE_LIB)),.$(DEPEND_FILE_POSTFIX_LIB)) is true"
endif
ifeq ($(suffix $(DEPEND_FILE_APP)),.$(DEPEND_FILE_POSTFIX_APP))
	@echo "ifeq($(suffix $(DEPEND_FILE_APP)),.$(DEPEND_FILE_POSTFIX_APP)) is true"
endif
# Not Working Case
ifeq ($(suffix $@),.test)
	@echo "ifeq ((suffix @),.testExt) is true"
endif

all : lib app

depend : $(DEPEND_FILE_LIB) $(depend_file_app)

lib : lib_shared lib_static
lib_shared : $(DEPEND_FILE_LIB) $(OUT_LIB_PATH_SHARED)
lib_static : $(DEPEND_FILE_LIB) $(OUT_LIB_PATH_STATIC)

ifeq ($(IS_SHARED),1)
lib_app_needs : lib_shared
else
lib_app_needs : lib_static
endif

lib_backup :
	@echo "==================================================="
	@echo "= Check Library and backup to avoid conflict"
ifeq ($(IS_SHARED),1)
	@if [ -e $(OUT_LIB_PATH_STATIC) ]; then \
		$(MV) $(OUT_LIB_PATH_STATIC) $(OUT_LIB_PATH_STATIC)_bak; \
		echo "= Backup Target: $(OUT_LIB_PATH_STATIC) to $(OUT_LIB_PATH_STATIC)_bak"; \
	fi;
else
#	@if [ -e $(OUT_LIB_PATH_SHARED) ]; then \
#		$(MV) $(OUT_LIB_PATH_SHARED) $(OUT_LIB_PATH_SHARED)_bak; \
#		echo "= Backup Target: $(OUT_LIB_PATH_SHARED) to $(OUT_LIB_PATH_SHARED)_bak"; \
#	fi;
	@if [ -e $(OUT_LIB_PATH_SHARED_VER) ]; then \
		$(MV) $(OUT_LIB_PATH_SHARED_VER) $(OUT_LIB_PATH_SHARED_VER)_bak; \
		echo "= Backup Target: $(OUT_LIB_PATH_SHARED_VER) to $(OUT_LIB_PATH_SHARED_VER)_bak"; \
	fi;
endif
	@echo "==================================================="

lib_restore :
	@echo "==================================================="
	@echo "= Check Library and restore"
ifeq ($(IS_SHARED),1)
	@if [ -e $(OUT_LIB_PATH_STATIC)_bak ]; then \
		$(MV) $(OUT_LIB_PATH_STATIC)_bak $(OUT_LIB_PATH_STATIC); \
		echo "= Restore Target: $(OUT_LIB_PATH_STATIC)_bak to $(OUT_LIB_PATH_STATIC)"; \
	fi;
else
#	@if [ -e $(OUT_LIB_PATH_SHARED)_bak ]; then \
#		$(MV) $(OUT_LIB_PATH_SHARED)_bak $(OUT_LIB_PATH_SHARED); \
#		echo "= Restore Target: $(OUT_LIB_PATH_SHARED)_bak to $(OUT_LIB_PATH_SHARED)"; \
#	fi;
	@if [ -e $(OUT_LIB_PATH_SHARED_VER)_bak ]; then \
		$(MV) $(OUT_LIB_PATH_SHARED_VER)_bak $(OUT_LIB_PATH_SHARED_VER); \
		echo "= Restore Target: $(OUT_LIB_PATH_SHARED_VER)_bak to $(OUT_LIB_PATH_SHARED_VER)"; \
	fi;
endif
	@echo "==================================================="

lib_notice :
	@echo "==================================================="
ifeq ($(IS_SHARED),1)
	@echo "= Set shell environements refer below sh command"
	@echo "export LD_LIBRARY_PATH='$(CURDIR)/$(dir ${OUT_LIB_PATH_SHARED})':\044LD_LIBRARY_PATH"
else
	@echo "= Nothing to setup for running"
endif
	@echo "==================================================="

app : lib_backup $(OUT_APP) lib_restore lib_notice

clean :
	@echo "==================================================="
	@echo "= TARGET: $@"
	@echo "==================================================="
	$(RM) -rf $(OBJS_DIR_NAME)
	$(RM) -rf $(OUT_DIR_NAME)
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="

$(DEPEND_FILE_LIB) : $(LIB_SRCS)
	@echo "==================================================="
	@echo "= Abstract Library Source Dependency"
	@echo "= Target: $@"
	@echo "= suffix: $(suffix $@)"
	@echo "==================================================="
	@`[ -d $(OBJS_DIR_NAME) ] || $(MKDIR) -p $(OBJS_DIR_NAME)`
	@$(RM) -f $@
	@for ITEM in $(LIB_ITEMS); do \
		echo "item: $$ITEM, src: $$ITEM.c, obj: $(OBJS_DIR_NAME)/$$ITEM.o"; \
		$(CC) -MM -MT $(OBJS_DIR_NAME)/$$ITEM.o $$ITEM.c $(CFLAGS) $(LIB_INC_DIRS) >> $@; \
	done
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="

$(DEPEND_FILE_APP) : $(APP_SRCS)
	@echo "==================================================="
	@echo "= Abstract Application Source Dependency"
	@echo "= Target: $@"
	@echo "==================================================="
	@`[ -d $(OBJS_DIR_NAME) ] || $(MKDIR) -p $(OBJS_DIR_NAME)`
	@$(RM) -f $@
	@for ITEM in $(APP_ITEMS); do \
		echo "item: $$ITEM, src: $$ITEM.c, obj: $(OBJS_DIR_NAME)/$$ITEM.o"; \
		$(CC) -MM -MT $(OBJS_DIR_NAME)/$$ITEM.o $$ITEM.c $(CFLAGS) $(APP_INC_DIRS) >> $@; \
	done
	@echo "DEPEND_FILE_APP: $(DEPEND_FILE_APP)"
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="

#########################################################
##### General Rule ######################################
##### Dependency is DEPEND_FILE_LIB DEPEND_FILE_APP #####
#########################################################
$(OBJS_DIR_NAME)/%.o :
	@echo "==================================================="
	@echo "= Compile: $@"
	@echo "= Source(1st depend. file): $<"
	@echo "= location: $(dir $@)"
	@echo "==================================================="
	@`[ -d $(dir $@) ] || $(MKDIR) -p $(dir $@)`
	$(if $(findstring $<, $(APP_SRCS)), \
		$(CC) $(CFLAGS) $(APP_INC_DIRS) -c $< -o $@, \
		$(CC) $(CFLAGS) $(LIB_INC_DIRS) -c $< -o $@)
	@echo "==================================================="
	@echo "= $@: Done"
	@echo "==================================================="

$(OUT_LIB_PATH_SHARED) : $(LIB_OBJS) # $(OUT_LIB_DIR)/$(SHARED_LIB_NAME)
	@echo "==================================================="
	@echo "= Make Shared Library"
	@echo "= Target: $@"
	@echo "= Depends: $(LIB_OBJS)"
	@echo "= location: $(dir $@)"
	@echo "==================================================="
	@`[ -d $(dir $@) ] || $(MKDIR) -p $(dir $@)`
	$(CC) -shared -Wl,-soname,$(SHARED_LIB_NAME) -o $@$(SHARED_LIB_NAME_VER_SUFFIX) $(LIB_OBJS)
	$(LN) -fs $(SHARED_LIB_NAME_VER) $@
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="

$(OUT_LIB_PATH_STATIC) : $(LIB_OBJS) # $(OUT_LIB_DIR)/$(STATIC_LIB_NAME)
	@echo "==================================================="
	@echo "= Make Static Library"
	@echo "= Target: $@"
	@echo "= Depends: $(LIB_OBJS)"
	@echo "= location: $(dir $@)"
	@echo "==================================================="
	@`[ -d $(dir $@) ] || $(MKDIR) -p $(dir $@)`
	$(AR) rcv $@ $(LIB_OBJS)
	$(RANLIB) $@
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="
	@echo "= Is not implementated yet"
	@echo "==================================================="
	@echo "= $@: Done"
	@echo "==================================================="

remove_shared_lib :
	@echo "==================================================="
	@echo "= TARGET: $@"
	@echo "==================================================="
	@echo "= Is not implementated yet"
	@echo "==================================================="
	@echo "= $@: Done"
	@echo "==================================================="

#########################################################
##### Linking Rule ######################################
#########################################################

$(OUT_DIR_NAME)/% : lib_app_needs $(APP_OBJS) # $(OUT_APP) = $(OUT_ITEMS_APP:%=$(OUT_DIR_NAME)/%)
	@echo "==================================================="
	@echo "= Linking: $@"
	@echo "= Object file: $(patsubst $(OUT_DIR_NAME)/%,%.o,$@)"
	@echo "==================================================="
	@`[ -d $(dir $@) ] || $(MKDIR) -p $(dir $@)`
	$(CC) -o $@ $(patsubst $(OUT_DIR_NAME)/%,%.o,$@) $(INC_LIB_PATH) $(INC_LIB_NAMES) $(LDFLAGS)
	@echo "==================================================="
	@echo "= Done"
	@echo "==================================================="

#########################################################
##### Dummy rule ########################################
#########################################################
%:
	@echo "==================================================="
	@echo "= TARGET: $@, Do nothing"
	@echo "==================================================="

ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), depend)
-include $(DEPEND_FILE_LIB)
-include $(DEPEND_FILE_APP)
endif
endif
