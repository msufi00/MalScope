import hashlib
from datetime import datetime, timezone
from pathlib import Path
import pefile
from malscope.analyzers import calculate_shannon_entropy


def compute_hashes(file_path: Path) -> dict:
    """Calculate MD5 and SHA-256 hashes using 8KB chunks."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def parse_pe_file(file_path: Path) -> dict:
    """Extract Windows PE metadata: hashes, imphash, entropy, headers, sections, and imports."""
    raw_file_bytes = file_path.read_bytes()
    overall_entropy = calculate_shannon_entropy(raw_file_bytes)

    result = {
        "file_name": file_path.name,
        "file_size": file_path.stat().st_size,
        "file_type": "Unknown / Non-PE",
        "hashes": compute_hashes(file_path),
        "imphash": "N/A",
        "overall_entropy": overall_entropy,
        "is_valid_pe": False,
        "error": None,
        "headers": {},
        "sections": [],
        "imports": {},
    }

    pe = None
    try:
        pe = pefile.PE(data=raw_file_bytes, fast_load=False)
        result["is_valid_pe"] = True
        result["imphash"] = pe.get_imphash() or "N/A"

        if pe.is_dll():
            result["file_type"] = "PE (Windows DLL)"
        elif pe.is_driver():
            result["file_type"] = "PE (Windows Driver)"
        else:
            result["file_type"] = "PE (Windows Executable)"

        compile_ts = pe.FILE_HEADER.TimeDateStamp
        compile_str = datetime.fromtimestamp(compile_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        result["headers"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "compile_timestamp": compile_str,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        }

        for section in pe.sections:
            sec_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            sec_entropy = calculate_shannon_entropy(section.get_data())
            result["sections"].append({
                "name": sec_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": sec_entropy,
                "high_entropy": sec_entropy > 7.0,
            })

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                funcs = [
                    imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal_{imp.ordinal}"
                    for imp in entry.imports
                ]
                result["imports"][dll_name] = funcs

    except pefile.PEFormatError as err:
        result["error"] = f"Not a valid Windows PE file ({err})"
    finally:
        if pe is not None:
            pe.close()

    return result