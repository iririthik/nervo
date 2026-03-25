# nervo_plugin.mk — builds nervo_gcc_plugin.so
#
# Usage:
#   make -f nervo_plugin.mk
#   make -f nervo_plugin.mk clean

GCC        ?= g++
PLUGIN_SRC  = nervo_gcc_plugin.c
PLUGIN_SO   = nervo_gcc_plugin.so

# GCC plugin headers live inside the GCC installation
GCC_PLUGIN_DIR := $(shell $(GCC) -print-file-name=plugin)

CXXFLAGS = \
    -std=c++14 \
    -fPIC \
    -shared \
    -fno-rtti \
    -O2 \
    -Wall \
    -Wno-literal-suffix \
    -I$(GCC_PLUGIN_DIR)/include

.PHONY: all clean

all: $(PLUGIN_SO)

$(PLUGIN_SO): $(PLUGIN_SRC)
	g++ $(CXXFLAGS) -o $@ $< -lpthread
	@echo "Built: $(PLUGIN_SO)"
	@echo "GCC plugin headers: $(GCC_PLUGIN_DIR)/include"

clean:
	rm -f $(PLUGIN_SO)
