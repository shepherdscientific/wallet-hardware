#!/bin/bash
# Generate production sdkconfig with secure boot v2 + flash encryption enabled.
#
# This script:
#   1. Runs a PlatformIO build to generate the base sdkconfig file
#   2. Applies production security overrides on top
#   3. Copies the result to sdkconfig.production
#
# Pre-requisites:
#   pip install platformio
#
# Usage:
#   ./scripts/gen_sdkconfig.sh         # generates sdkconfig.production
#   ./scripts/gen_sdkconfig.sh dev     # generates sdkconfig.dev (no secure boot)
#
# After running, build with:
#   pio run -e production -t upload
#
# WARNING: Do NOT burn eFuses until you have verified the build boots correctly.
# Secure boot eFuse burning is IRREVERSIBLE and will brick unsigned firmware.

set -euo pipefail

MODE="${1:-production}"
SDKCONFIG_OUT="sdkconfig.${MODE}"
DEFAULTS_FILE="sdkconfig.defaults.${MODE}"

if [ ! -f "$DEFAULTS_FILE" ]; then
    echo "Error: $DEFAULTS_FILE not found"
    exit 1
fi

echo "=== Generating $SDKCONFIG_OUT ==="

# Build to generate base sdkconfig
pio run -e "$MODE" 2>&1 | tail -5

# Find generated sdkconfig
GENERATED=$(find .pio/build/"$MODE" -maxdepth 1 -name "sdkconfig" 2>/dev/null | head -1)
if [ -z "$GENERATED" ]; then
    # PlatformIO with Arduino may put sdkconfig in a framework dir
    GENERATED=$(find .pio -path "*/$MODE/sdkconfig*" -not -name "sdkconfig.h" 2>/dev/null | head -1)
fi

if [ -z "$GENERATED" ]; then
    echo "Error: sdkconfig not found after build. Generating from defaults only."
    cp "$DEFAULTS_FILE" "$SDKCONFIG_OUT"
else
    echo "Found generated sdkconfig: $GENERATED"
    cp "$GENERATED" "$SDKCONFIG_OUT"

    # Append overrides (merge: last definition wins in Kconfig)
    echo "" >> "$SDKCONFIG_OUT"
    echo "# === Production Security Overrides ===" >> "$SDKCONFIG_OUT"
    cat "$DEFAULTS_FILE" >> "$SDKCONFIG_OUT"
fi

echo "=== $SDKCONFIG_OUT ready ==="
echo ""
echo "To build with secure boot:"
echo "  1. Edit $SDKCONFIG_OUT and set CONFIG_SECURE_BOOT_SIGNING_KEY=<path>"
echo "  2. pio run -e $MODE"
echo ""
if [ "$MODE" = "production" ]; then
    echo "WARNING: Secure boot eFuse burning is IRREVERSIBLE."
    echo "  Test that the firmware boots normally BEFORE burning any eFuses."
    echo "  See README.md for the complete eFuse burning and key ceremony procedure."
fi
