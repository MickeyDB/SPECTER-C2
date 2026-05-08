# SPECTER Implant Build System
# Cross-compilation using MinGW-w64 targeting Windows x86-64 PIC blob

CC      = x86_64-w64-mingw32-gcc
LD      = $(if $(shell command -v x86_64-w64-mingw32-ld 2>/dev/null),x86_64-w64-mingw32-ld,ld)
OBJCOPY = $(if $(shell command -v x86_64-w64-mingw32-objcopy 2>/dev/null),x86_64-w64-mingw32-objcopy,objcopy)
PYTHON  = $(if $(shell command -v python3 2>/dev/null),python3,python)

# Set DEV=1 to skip anti-analysis checks (for testing on VMs)
ifdef DEV
  DEV_FLAGS = -DSPECTER_DEV_BUILD
else
  DEV_FLAGS =
endif

ifdef BAREBONE
  BAREBONE_FLAGS = -DSPECTER_BAREBONE -ffunction-sections -fdata-sections
  BAREBONE_LDFLAGS = --gc-sections
else
  BAREBONE_FLAGS =
  BAREBONE_LDFLAGS =
endif

ifdef BAREBONE_MODULE_OVERLOAD
  BAREBONE_FLAGS += -DSPECTER_BAREBONE_MODULE_OVERLOAD
endif

ifdef BAREBONE_MODULES
  BAREBONE_FLAGS += -DSPECTER_BAREBONE_MODULES
endif

ifdef CLEAN_SLEEP_ENTRY
  BAREBONE_FLAGS += -DSPECTER_LAB_CLEAN_SLEEP_ENTRY
endif

ifdef BENIGN_SLEEP
  BAREBONE_FLAGS += -DSPECTER_LAB_BENIGN_SLEEP
endif

ifdef OFFTHREAD_WAIT
  BAREBONE_FLAGS += -DSPECTER_LAB_OFFTHREAD_WAIT
endif

ifdef CALLBACK_TICK
  BAREBONE_FLAGS += -DSPECTER_LAB_CALLBACK_TICK
endif

CFLAGS  = -Wall -Werror -Wno-unused-function -Os -fno-stack-protector \
          -funwind-tables \
          -fno-ident -fpack-struct=8 -falign-functions=1 -falign-jumps=1 \
          -falign-labels=1 -falign-loops=1 -fno-common -nostdlib -nostdinc \
          -ffreestanding -masm=intel -std=c11 -DWIN32_LEAN_AND_MEAN \
          -mno-stack-arg-probe $(DEV_FLAGS) $(BAREBONE_FLAGS) \
          -Icore/include

LDFLAGS = -T scripts/linker.ld -nostdlib --no-dynamic-linker --image-base=0 \
          --disable-auto-import --disable-runtime-pseudo-reloc \
          --sort-section=name \
          -Map=build/specter.map $(BAREBONE_LDFLAGS)

SRC_DIR   = core/src
EVA_DIR   = core/src/evasion
BUS_DIR   = core/src/bus
COMMS_DIR = core/src/comms
ASM_DIR   = core/asm
BUILD_DIR = build

# Unity build: compile all C sources as a single translation unit to
# eliminate MinGW .refptr pseudo-GOT entries (which break PIC loading).
# The assembly stub is compiled separately.
UNITY_SRC = $(SRC_DIR)/unity.c
ASM_SRCS  = $(wildcard $(ASM_DIR)/*.S)

UNITY_OBJ = $(BUILD_DIR)/unity.o
ASM_OBJS  = $(patsubst $(ASM_DIR)/%.S,$(BUILD_DIR)/%.o,$(ASM_SRCS))
OBJS      = $(UNITY_OBJ) $(ASM_OBJS)

# Output
TARGET_ELF = $(BUILD_DIR)/specter.elf
TARGET_BIN = $(BUILD_DIR)/specter.bin

# Test configuration (native host compiler)
TEST_CC     = gcc
TEST_CFLAGS = -Wall -Werror -g -std=c11 -DTEST_BUILD -Icore/include
TEST_DIR    = tests
TEST_BIN_DIR = build/tests

# Module configuration
MOD_DIR       = modules
MOD_BUILD_DIR = $(BUILD_DIR)/modules
MOD_INCLUDE   = -I$(MOD_DIR)/include
MOD_LDSCRIPT  = scripts/module_linker.ld
MOD_LDFLAGS   = -T $(MOD_LDSCRIPT) -nostdlib --no-dynamic-linker --image-base=0

# Discover all module source directories (each dir with a .c file)
MOD_SRCS   = $(wildcard $(MOD_DIR)/*/$(notdir $(wildcard $(MOD_DIR)/*/*.c)))
MOD_NAMES  = $(filter-out include,$(patsubst $(MOD_DIR)/%/,%,$(sort $(dir $(wildcard $(MOD_DIR)/*/*.c)))))
MOD_BINS   = $(patsubst %,$(MOD_BUILD_DIR)/%.bin,$(MOD_NAMES))

.PHONY: all clean size test modules modules-clean stubs stubs-clean pic-loader features

all: $(TARGET_BIN) features size

features:
	@mkdir -p $(BUILD_DIR)
	@printf "callback_tick=%s\n" "$(if $(CALLBACK_TICK),1,0)" > $(BUILD_DIR)/specter.features
	@printf "barebone=%s\n" "$(if $(BAREBONE),1,0)" >> $(BUILD_DIR)/specter.features
	@printf "barebone_modules=%s\n" "$(if $(BAREBONE_MODULES),1,0)" >> $(BUILD_DIR)/specter.features
	@printf "dev=%s\n" "$(if $(DEV),1,0)" >> $(BUILD_DIR)/specter.features

modules: $(MOD_BUILD_DIR) $(MOD_BINS)
	@echo "=== Built $(words $(MOD_BINS)) module(s) ==="
	@$(PYTHON) scripts/list_module_sizes.py $(MOD_BINS)

$(MOD_BUILD_DIR):
	mkdir -p $(MOD_BUILD_DIR)

# Unity build: single C compilation unit
$(UNITY_OBJ): $(UNITY_SRC) $(wildcard $(SRC_DIR)/*.c $(EVA_DIR)/*.c $(BUS_DIR)/*.c $(COMMS_DIR)/*.c)
	$(CC) $(CFLAGS) -c $< -o $@

# Assembly stubs compiled separately
$(BUILD_DIR)/%.o: $(ASM_DIR)/%.S
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_ELF): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(TARGET_BIN): $(TARGET_ELF)
	$(OBJCOPY) -O binary -j .text $< $@
	$(PYTHON) scripts/extract_shellcode.py $@

# Pattern rule: compile each module .c -> .elf -> .bin
# Each module is a single .c file in modules/<name>/<name>.c
$(MOD_BUILD_DIR)/%.bin: $(MOD_BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary -j .text $< $@

$(MOD_BUILD_DIR)/%.elf: $(MOD_DIR)/%/*.c | $(MOD_BUILD_DIR)
	$(CC) $(CFLAGS) $(MOD_INCLUDE) -c $(wildcard $(MOD_DIR)/$*/*.c) -o $(MOD_BUILD_DIR)/$*.o
	$(LD) $(MOD_LDFLAGS) -o $@ $(MOD_BUILD_DIR)/$*.o

clean:
	$(PYTHON) scripts/clean_build.py $(BUILD_DIR)

modules-clean:
	rm -rf $(MOD_BUILD_DIR)

# ---- Stub targets (pre-compiled PE templates) ----

stubs:
	$(MAKE) -C stubs

stubs-clean:
	$(MAKE) -C stubs clean

size: $(TARGET_BIN)
	@echo "--- SPECTER PIC Blob Size ---"
	@$(PYTHON) scripts/print_size.py "$(TARGET_BIN)"
	@echo " bytes"

# ---- Test targets (native host compiler) ----

$(TEST_BIN_DIR):
	mkdir -p $(TEST_BIN_DIR)

pic-loader: $(TEST_BIN_DIR)/pic_loader.exe

$(TEST_BIN_DIR)/pic_loader.exe: $(TEST_DIR)/pic_loader.c | $(TEST_BIN_DIR)
	$(CC) -Wall -Werror -O2 -std=c11 -o $@ $<

$(TEST_BIN_DIR)/test_bus_api: $(TEST_DIR)/test_bus_api.c $(SRC_DIR)/crypto.c $(BUS_DIR)/bus_api.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_ed25519: $(TEST_DIR)/test_ed25519.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto_sign.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_coff_loader: $(TEST_DIR)/test_coff_loader.c $(BUS_DIR)/loader.c $(BUS_DIR)/beacon_shim.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto_sign.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_lifecycle: $(TEST_DIR)/test_lifecycle.c $(BUS_DIR)/lifecycle.c $(BUS_DIR)/bus_api.c $(BUS_DIR)/guardian.c $(BUS_DIR)/loader.c $(BUS_DIR)/beacon_shim.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto_sign.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -o $@ $^

$(TEST_BIN_DIR)/test_profile: $(TEST_DIR)/test_profile.c $(SRC_DIR)/profile.c $(SRC_DIR)/transform.c $(SRC_DIR)/crypto.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c $(SRC_DIR)/sleep.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -Wno-unused-variable -o $@ $^

$(TEST_BIN_DIR)/test_module_args: $(TEST_DIR)/test_module_args.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_collect_safe_fail: $(TEST_DIR)/test_collect_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_socks5_safe_fail: $(TEST_DIR)/test_socks5_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_exfil_safe_fail: $(TEST_DIR)/test_exfil_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_token_safe_fail: $(TEST_DIR)/test_token_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_inject_safe_fail: $(TEST_DIR)/test_inject_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_lateral_safe_fail: $(TEST_DIR)/test_lateral_safe_fail.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -I$(MOD_DIR)/include -o $@ $^

$(TEST_BIN_DIR)/test_beacon_shim: $(TEST_DIR)/test_beacon_shim.c $(BUS_DIR)/beacon_shim.c $(SRC_DIR)/string.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -o $@ $^

$(TEST_BIN_DIR)/test_extended_bof: $(TEST_DIR)/test_extended_bof.c $(BUS_DIR)/beacon_shim.c $(BUS_DIR)/clr.c $(BUS_DIR)/inline_asm.c $(SRC_DIR)/string.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -o $@ $^

$(TEST_BIN_DIR)/test_channels: $(TEST_DIR)/test_channels.c $(COMMS_DIR)/dns.c $(COMMS_DIR)/smb.c $(COMMS_DIR)/websocket.c $(SRC_DIR)/crypto.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -o $@ $^

$(TEST_BIN_DIR)/test_sleep: $(TEST_DIR)/test_sleep.c $(SRC_DIR)/sleep.c $(SRC_DIR)/crypto.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -Wno-unused-variable -o $@ $^

$(TEST_BIN_DIR)/test_failover: $(TEST_DIR)/test_failover.c $(SRC_DIR)/comms.c $(SRC_DIR)/crypto.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c $(SRC_DIR)/profile.c $(SRC_DIR)/transform.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -Wno-unused-variable -o $@ $^

$(TEST_BIN_DIR)/test_antianalysis: $(TEST_DIR)/test_antianalysis.c $(EVA_DIR)/antianalysis.c $(SRC_DIR)/string.c $(SRC_DIR)/hash.c | $(TEST_BIN_DIR)
	$(TEST_CC) $(TEST_CFLAGS) -Wno-unused-function -o $@ $^

test: $(TEST_BIN_DIR)/test_bus_api $(TEST_BIN_DIR)/test_ed25519 $(TEST_BIN_DIR)/test_coff_loader $(TEST_BIN_DIR)/test_lifecycle $(TEST_BIN_DIR)/test_profile $(TEST_BIN_DIR)/test_module_args $(TEST_BIN_DIR)/test_collect_safe_fail $(TEST_BIN_DIR)/test_socks5_safe_fail $(TEST_BIN_DIR)/test_exfil_safe_fail $(TEST_BIN_DIR)/test_token_safe_fail $(TEST_BIN_DIR)/test_inject_safe_fail $(TEST_BIN_DIR)/test_lateral_safe_fail $(TEST_BIN_DIR)/test_beacon_shim $(TEST_BIN_DIR)/test_extended_bof $(TEST_BIN_DIR)/test_channels $(TEST_BIN_DIR)/test_sleep $(TEST_BIN_DIR)/test_failover $(TEST_BIN_DIR)/test_antianalysis
	@echo "=== Running Bus API Tests ==="
	@$(TEST_BIN_DIR)/test_bus_api
	@echo "=== Running Ed25519 Tests ==="
	@$(TEST_BIN_DIR)/test_ed25519
	@echo "=== Running COFF Loader Tests ==="
	@$(TEST_BIN_DIR)/test_coff_loader
	@echo "=== Running Lifecycle Tests ==="
	@$(TEST_BIN_DIR)/test_lifecycle
	@echo "=== Running Profile & Transform Tests ==="
	@$(TEST_BIN_DIR)/test_profile
	@echo "=== Running Module Args Tests ==="
	@$(TEST_BIN_DIR)/test_module_args
	@echo "=== Running Collect Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_collect_safe_fail
	@echo "=== Running SOCKS5 Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_socks5_safe_fail
	@echo "=== Running Exfil Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_exfil_safe_fail
	@echo "=== Running Token Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_token_safe_fail
	@echo "=== Running Inject Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_inject_safe_fail
	@echo "=== Running Lateral Safe-Failure Tests ==="
	@$(TEST_BIN_DIR)/test_lateral_safe_fail
	@echo "=== Running Beacon Shim Tests ==="
	@$(TEST_BIN_DIR)/test_beacon_shim
	@echo "=== Running Extended BOF API Tests ==="
	@$(TEST_BIN_DIR)/test_extended_bof
	@echo "=== Running DNS Channel Tests ==="
	@$(TEST_BIN_DIR)/test_channels
	@echo "=== Running Sleep Controller Tests ==="
	@$(TEST_BIN_DIR)/test_sleep
	@echo "=== Running Channel Failover Tests ==="
	@$(TEST_BIN_DIR)/test_failover
	@echo "=== Running Anti-Analysis Tests ==="
	@$(TEST_BIN_DIR)/test_antianalysis
