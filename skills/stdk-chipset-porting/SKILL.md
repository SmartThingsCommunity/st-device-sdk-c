---
name: stdk-chipset-porting
description: Ports the SmartThings Device SDK (STDK) to a new, unsupported chipset by fetching the chipset's firmware/SDK, confirming it targets that chipset, analyzing its real APIs, and writing a complete, verified porting layer under src/port/bsp/{chipset}/.
metadata:
  version: "1.0.0"
---

# STDK Chipset Porting Skill

Helps port STDK to a chipset that isn't already supported, by generating a real, compilable porting layer — not a template.

Full API reference, directory layout, and build integration steps live in [doc/porting_guide.md](../../doc/porting_guide.md). This skill adds the agent workflow on top of that guide.

## When to Use

- User asks to port STDK to a chipset not listed in `doc/porting_guide.md`'s "Currently Ported Chipsets" section.

## Step 0: Firmware Link Is Mandatory

Before doing anything else, check whether the user's request includes a link to the target chipset's SDK source or API documentation.

- **If no link was given**: ask the user for it. Do not proceed, and do not generate any code.
- **If the user still doesn't provide one after being asked**: end the task with "cannot help". Accurate porting code needs the chipset's actual APIs, and generic code would be a guess.
- **If a link was given**: continue to Step 1. The link is not trusted yet; Step 1 checks it is the right SDK.

## Step 1: Fetch the SDK and Confirm It Matches

**Clone the repository; do not read it through the GitHub REST API** — unauthenticated calls are rate limited (HTTP 403). If the link is documentation rather than a repo, read the pages and note in Step 3 that the SDK-backed checks could not run.

**Confirm the SDK targets this exact chipset or its family before reading any API.** Look for evidence in the clone: the README or a supported-SoC table lists it, or project/HAL/target directory names match. Vendor family names often differ from the part number, so check which family the part belongs to. If the evidence is missing or points to a different family, **stop and ask the user for the correct SDK link**, saying what you found. A nearby family looks plausible but uses different APIs.

Then find the SDK's real APIs for WiFi (init/scan/connect/events/DHCP/MAC), BLE, file system, non-volatile storage, system time/reboot/version, RNG, and debug/heap. Don't write calls from memory: grep the SDK and read each declaration (parameter types, return codes, whether it completes via a callback) before using it. If an expected symbol doesn't exist, find the real equivalent or tell the user.

Reference [src/port/bsp/esp32/](../../src/port/bsp/esp32/) as a working example of how a real chipset SDK gets mapped to these STDK signatures.

## Step 2: Write the Implementation

First run the script with the chipset name and firmware link to get the manifest:

```bash
node skills/stdk-chipset-porting/validate_and_scaffold.js --chipset <name> --firmware-link <url>
```

On success it prints a JSON manifest: the target directory (`src/port/bsp/{chipset}/`), the 8 required files (7 `.c` files + `CMakeLists.txt`) with the exact STDK function signatures each must implement (read from this repo's `src/include/bsp/*.h`, so they match the SDK version), and `also_required` (the build wiring listed below). It doesn't write any C code; the implementation is yours. If it exits with an error, relay the `message` field to the user (e.g. re-ask for the firmware link, or tell them the chipset is already supported) and stop.

For every file in the manifest, write a complete implementation:

- Every required signature must have a real, working function body calling the SDK APIs from Step 1 — no `TODO`/stub bodies. All 7 `.c` files must exist, including BLE.
- Use sensible defaults where the firmware doesn't dictate a choice (e.g. WiFi auth modes, BLE MTU, NV path scheme) and comment each one.
- Include the Apache 2.0 license header (copy from `src/port/bsp/esp32/`).
- Write `CMakeLists.txt` modeled on [esp32](../../src/port/bsp/esp32/CMakeLists.txt) and [bk7236](../../src/port/bsp/bk7236/CMakeLists.txt): the BLE source goes inside `if(CONFIG_STDK_IOT_CORE_EASYSETUP_BLE)` with the vendor's Bluetooth library, and every `.c` file must be named.
- Add the build wiring listed in `also_required` (Kconfig entry, `component.cmake` branch, `iot_bsp_custom.h`), or the build can never select the port. See "Registering a new BSP in the build" in `doc/porting_guide.md`.
- **Stay in scope** — Write only to `src/port/bsp/{chipset}/`, `src/include/bsp/{chipset}/`, `src/Kconfig` and `src/component.cmake`, so core code and other ports are unaffected.

### Trace each behavior to a vendor call

The verifier can't see whether the port *works*. Before Step 3, read "Behavioral requirements" in `doc/porting_guide.md` and, for every bullet, find the vendor call or callback that provides it. In your final summary, list each Wi-Fi, BLE and NV/FS bullet with the function and line that satisfies it (e.g. "BLE write path: `<vendor GATT write handler>` → `write_cb`, registered at `<line>`"). If a bullet has no vendor equivalent, record it as an assumption in the summary. The BLE UUIDs, advertising layout and the soft-AP-only meaning of the Wi-Fi callback are fixed by the core, so copy them from the guide.

Above each vendor call, put a one-line comment with the SDK declaration you matched it against (the prototype copied from the header), so a reviewer can check argument types by eye.

## Step 3: Verify, Then Summarize

Run the verifier with the cloned SDK:

```bash
node skills/stdk-chipset-porting/validate_and_scaffold.js --chipset <name> --verify --sdk-dir <path-to-cloned-sdk>
```

**The port is done when the verifier exits 0.** If it reports errors, fix the code and rerun until it does; don't present the port as finished while the last run had errors. Don't edit `validate_and_scaffold.js`, the existing STDK headers in `src/include` or the SDK clone to make a check pass; the fix belongs in the port. When a message names a vendor symbol, header or link library that doesn't exist, find the real one in the SDK (grep it, read the declaration) rather than renaming the guess. When it reports an argument-count mismatch, re-read that function's declaration in the SDK header and match its parameters.

It checks that:
- every file and function exists, with no stub bodies and the exact return/parameter types from the manifest;
- the build wiring is present;
- every `IOT_*`/`iot_*` name exists in `src/include`;
- every vendor include, function and constant exists in the SDK, and each vendor call has the argument count the SDK declares;
- the libraries named in `target_link_libraries` exist in the vendor build;
- `iot_bsp_wifi_get_status()` sets `last_disconnected_reason` and doesn't hard-code RSSI to 0, and the Wi-Fi and BLE callbacks (`write_cb`, `conn_cb`, the Wi-Fi event callback) are invoked from a handler that something registers or calls;
- the file system doesn't hash file names into shared slots.

**This is a static text check, not a compile.** It cannot tell that a vendor call has the right argument *types*, that an event fires on the right path, or that the GATT service has the right UUIDs; that is what the Step 2 trace is for. Re-read each vendor call against its declaration, then compile each port `.c` file to an object (`-c`, no link) with the SDK's own toolchain and include paths:

- **Define the guard macros** — Pass the same `CONFIG_STDK_IOT_CORE_*` macros the build wiring sets. Without them the `#ifdef` guards compile each file to nothing.
- **Turn on type warnings** — Use `-Werror=implicit-function-declaration -Werror=incompatible-pointer-types` to catch wrong argument types and invented functions.
- **Leave the SDK untouched** — If the port needs an option that is off by default (such as a file system), pass it as a `-D` flag and list it in the summary as a build prerequisite.
- **Report what ran** — Name the compiler, the files compiled and any extra defines. If no compile was possible, say so in the summary and give the reason.

Then summarize for the user: the files and wiring created; the SDK used and the evidence it matches the chipset; the verifier's final `summary` block pasted verbatim (including `skipped_checks`) and whether the files were compiled (compiler, defines, any prerequisites); every default or assumption to review before flashing; that the port has not been run on hardware, unless it has; and the build steps from `doc/porting_guide.md`.

## Implementation Tips

- **Guard vendor headers** — Wrap vendor includes in `#ifdef CONFIG_STDK_IOT_CORE_*` so they only pull in when building with that vendor SDK.
- **Include what you use** — e.g. `<stdlib.h>` for `malloc`, and `<sys/time.h>` as well as `<time.h>` for `gettimeofday()`/`settimeofday()`.
- **Read each function's contract in the header** — The doc comments in `src/include/bsp/*.h` are authoritative for behavior, not just signatures. Example: `iot_bsp_wifi_get_status()` is polled every few seconds, must return quickly without blocking, and must fill every field of `iot_wifi_info` (using the `*_UNKNOWN` values when unavailable). Check the esp32 and bk7236 ports for how they honor it.
- **Callbacks must fire** — For WiFi and BLE, store the callback in a static global **and** invoke it from the vendor SDK's event handler (registered in init). Otherwise STDK never learns of connect/disconnect.
- **NV data and the file system must agree** — Decide whether the chipset uses NVS key-value (return a key like `"DeviceID"`) or file paths (return `"/stnv/device_id"`), and use the same scheme in `iot_bsp_nv_get_data_path()` and `iot_bsp_fs_*`.
- **Don't invent platform facts** — Take partition names, drive letters, flash addresses and frequency bands from the SDK, or use a documented configurable default and list it in the summary.
- **Keep secrets out of logs** — Don't log Wi-Fi passwords, keys or certificates, and clear password buffers once the connection attempt is done.
- **Error codes** — Return `iot_error_t` values from `src/include/iot_error.h`, not `int` or `errno`.
- **Study order** — Read `src/port/bsp/posix/` first (simplest contract), then `esp32/`, before writing your port.

## References

- [doc/porting_guide.md](../../doc/porting_guide.md) — API specs, directory layout, build integration, supported chipset list.
- [src/port/bsp/esp32/](../../src/port/bsp/esp32/) and [src/port/bsp/bk7236/](../../src/port/bsp/bk7236/) — reference implementations.

## Version

- Version: 1.0.0 (2026-11-05)
- Initial versioned release. Bump the `metadata.version` front matter and this section together on every change (semver: MAJOR for breaking changes to the trigger or output format, MINOR for new capabilities, PATCH for fixes and wording).
