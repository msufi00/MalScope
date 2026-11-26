# MalScope Test Results

**Course:** IKB31603 Ethical Hacking | **Group:** GoodGuys | **Tester:** Azim
**Tool under test:** MalScope (static malware analyzer, CLI and local Web UI)
**Test date:** 25 Nov 2026

All samples are harmless: EICAR test string, a copy of a normal Windows program, a UPX-packed copy of it, and zero-filled dummy files. No real malware was used and nothing was executed.

---

## Test Result Summary Table

| Sample | What it tests | Expected | Valid test? | Notes |
|---|---|---|---|---|
| `empty.exe` (0 bytes) | Empty file handling | Rejected with a clear message, no crash | Yes | **CLI:** `[ERROR] Empty file (0 bytes) - cannot perform static PE analysis.` **Web UI:** "Empty file (0 bytes) cannot be analyzed." No crash. Matches expected. |
| `big_49mb.exe` (51,380,224 bytes) | Just under the 50 MB cap | Accepted, then UNSUPPORTED (not a PE) | Yes | **CLI and Web UI:** UNSUPPORTED, 0/100, entropy 0.0000, "DOS Header magic not found". Accepted, so the cap is 50 MiB, not 50,000,000 bytes. Matches expected. |
| `big_51mb.exe` (53,477,376 bytes) | Over the 50 MB cap | Rejected before analysis | Yes | **CLI:** `[ERROR] File size exceeds the safe 50 MB limit.` **Web UI:** "File exceeds the maximum safe limit of 50 MB." Matches expected. |
| `hostname.exe` (40,960 bytes) | Normal Windows baseline | CLEAN, low score | Yes | **CLI and Web UI:** CLEAN, 0/100, entropy 2.4734, 7 sections, 0 MITRE tactics, 0 IOCs. Matches expected. |
| `hostname_upx.exe` (10,752 bytes) | UPX-packed file | High entropy, `UPX0`/`UPX1` sections, higher score than the baseline | Yes | Packed with `--force` because `hostname.exe` has GUARD_CF. **CLI:** SUSPICIOUS, 28/100, `UPX1` entropy 7.4096, 3 sections, imports `LoadLibraryA`, `GetProcAddress`, `VirtualProtect` (1 tactic, 2 techniques). **Web UI:** CLEAN, 20/100, 0 tactics (scan taken at 03:43Z, earlier than the CLI scan at 06:28Z). The two interfaces disagree, so re-run the Web UI scan and update this row. |
| `doesnotexist.exe` | Wrong path | Clear error message | Yes | **CLI:** `[ERROR] File not found: ...\samples\doesnotexist.exe`. Not tested in the Web UI (files are chosen from a file dialog). Matches expected. |
| `eicar.com` (68 bytes) | EICAR signature rule on a non-PE file | MALICIOUS, 100/100 | Yes | **CLI and Web UI:** MALICIOUS, 100/100, "EICAR Standard Anti-Virus Test Signature detected". MD5 `44d88612...` matches the standard EICAR file. Matches README. |
| `eicar.com` (first attempt, 60 bytes) | Broken EICAR string | UNSUPPORTED | No | PowerShell removed `$EICAR` and `$H` from the string inside double quotes, so the file was 60 bytes and the signature rule did not fire. Result was UNSUPPORTED, 0/100. Replaced by the 68-byte file above. |
| `README.md` (Web UI) | Wrong file type | Rejected | Yes | **Web UI:** "Unsupported file extension '.md'. Allowed types: .exe, .dll, .sys, .com". Rejected by extension before any content check. Not tested in the CLI. Matches expected. |

---

## Preparations

All commands were run from the MalScope project folder with the virtual environment active.

1. **Empty file:** created `samples/empty.exe` (0 bytes).
   ![Create empty file](test_results_images/prep-01-create-empty-file.png)
2. **Size-cap files:** created `big_51mb.exe` (51 x 1024 x 1024 bytes) and `big_49mb.exe` (49 x 1024 x 1024 bytes).
   ![Create size-cap files](test_results_images/prep-02-create-size-cap-files.png)
3. **UPX:** installed UPX (Ultimate Packer for eXecutables), an open-source command-line tool that compresses executable files.
   ![Install UPX](test_results_images/prep-03-install-upx.png)
4. **Baseline:** copied `hostname.exe` from Windows into `samples/`.
   ![Copy hostname.exe](test_results_images/prep-04-copy-hostname.png)
5. **Packing:** UPX refused the first attempt (`GUARD_CF enabled PE files are not supported`), so the file was packed again with `--force`.
   ![UPX GUARD_CF error](test_results_images/prep-05-upx-guard-cf-error.png)
6. **EICAR:** created `samples/eicar.com`.
   ![Create eicar.com](test_results_images/prep-06-create-eicar.png)
7. **Samples folder:** every file in `samples/` was tested (`.gitkeep` excluded).
   ![Samples folder](test_results_images/prep-07-samples-folder.png)

---

## Command-Line Interface (CLI)

### `empty.exe`

![CLI empty.exe](test_results_images/cli-01-empty.png)



### Over 50 MB (`big_51mb.exe`)

![CLI over 50 MB](test_results_images/cli-02-over-50mb.png)



### Under 50 MB (`big_49mb.exe`)

![CLI under 50 MB](test_results_images/cli-03-under-50mb.png)



### `hostname.exe`

![CLI hostname.exe](test_results_images/cli-04-hostname.png)



### `hostname_upx.exe`

![CLI hostname_upx.exe](test_results_images/cli-05-hostname-upx.png)




### Wrong path

Shows the error message "File not found".

![CLI wrong path](test_results_images/cli-06-wrong-path.png)



### `eicar.com`

![CLI eicar.com](test_results_images/cli-07-eicar.png)

---

## Web User Interface (Web UI)

### Start the server

![Start the server](test_results_images/web-01-start-server.png)


### MalScope Web UI

![MalScope Web UI](test_results_images/web-02-home.png)


### `empty.exe`

Selected:

![empty.exe selected](test_results_images/web-03-empty-selected.png)


Result: the empty file cannot be analyzed.

![empty.exe result](test_results_images/web-04-empty-result.png)

### File under 50 MB (`big_49mb.exe`)

Selected:

![Under 50 MB selected](test_results_images/web-05-under-50mb-selected.png)


Result: the under-50 MB scan result.

![Under 50 MB result](test_results_images/web-06-under-50mb-result.png)


### File above 50 MB (`big_51mb.exe`)

Selected:

![Over 50 MB selected](test_results_images/web-07-over-50mb-selected.png)


Result: the file exceeds the maximum limit.

![Over 50 MB result](test_results_images/web-08-over-50mb-result.png)


### `hostname.exe`

Selected:

![hostname.exe selected](test_results_images/web-09-hostname-selected.png)


Result:

![hostname.exe result](test_results_images/web-10-hostname-result.png)


### UPX file (`hostname_upx.exe`)

Selected:

![hostname_upx.exe selected](test_results_images/web-11-upx-selected.png)


Result:

![hostname_upx.exe result](test_results_images/web-12-upx-result.png)


### Non-PE file (`README.md`)

Selected:

![README.md selected](test_results_images/web-13-readme-selected.png)


Result: error message for an unsupported file.

![README.md result](test_results_images/web-14-readme-result.png)

### `eicar.com`

Selected:

![eicar.com selected](test_results_images/web-15-eicar-selected.png)

Result:

![eicar.com result](test_results_images/web-16-eicar-result.png)
