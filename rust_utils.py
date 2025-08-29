import logging
import pprint
from constants import causes, csrs, csrs32
from shared_utils import InstrDict

pp = pprint.PrettyPrinter(indent=4)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:: %(message)s")


def make_rust(instr_dict: InstrDict):
    # Initialize strings for different instruction categories
    # We'll use a cleaner hierarchy: length -> XLEN -> opcode

    # Compressed instructions (16-bit)
    compressed_instrs = ""
    compressed_32_instrs = ""
    compressed_64_instrs = ""

    # Full instructions (32-bit) - grouped by opcode
    full_instrs_by_opcode = {}
    full_32_instrs_by_opcode = {}
    full_64_instrs_by_opcode = {}

    for i in instr_dict:
        name = i.replace("_", ".")
        variables: list[str] = []
        for v in instr_dict[i]["variable_fields"]:
            variables.extend(canonicalize_arg(v))

        # Create the instruction spec string
        instr_spec = (
            f'    Spec::new("{name}", {instr_dict[i]["mask"]}, '
            f'{instr_dict[i]["match"]}, vec![{", ".join(variables)}]),\n'
        )

        # Determine instruction characteristics
        is_compressed = instr_dict[i]["length"] == 16
        is_full = instr_dict[i]["length"] == 32
        is_32_specific = "32" in instr_dict[i]["extension"][0]
        is_64_specific = "64" in instr_dict[i]["extension"][0]

        # Categorize instructions - each instruction goes to exactly one category
        if is_compressed:
            if is_32_specific:
                compressed_32_instrs += instr_spec
            elif is_64_specific:
                compressed_64_instrs += instr_spec
            else:
                # General compressed instruction (not XLEN-specific)
                compressed_instrs += instr_spec
        elif is_full:
            opcode = instr_dict[i]["opcode"]
            if is_32_specific:
                if opcode not in full_32_instrs_by_opcode:
                    full_32_instrs_by_opcode[opcode] = ""
                full_32_instrs_by_opcode[opcode] += instr_spec
            elif is_64_specific:
                if opcode not in full_64_instrs_by_opcode:
                    full_64_instrs_by_opcode[opcode] = ""
                full_64_instrs_by_opcode[opcode] += instr_spec
            else:
                # General full instruction (not XLEN-specific)
                if opcode not in full_instrs_by_opcode:
                    full_instrs_by_opcode[opcode] = ""
                full_instrs_by_opcode[opcode] += instr_spec

    # Build opcode sections for full instructions
    full_opcode_sections = ""
    for opcode in sorted(full_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        full_opcode_sections += (
            f'pub static RV_ISA_SPECS_GENERIC_FULL_OPCODE_{opcode_str}: '
            f'Lazy<Vec<Spec>> = Lazy::new(|| vec![\n{full_instrs_by_opcode[opcode]}]);\n'
        )
        full_opcode_sections += "\n"

    full_32_opcode_sections = ""
    for opcode in sorted(full_32_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        full_32_opcode_sections += (
            f'pub static RV_ISA_SPECS_32_FULL_OPCODE_{opcode_str}: '
            f'Lazy<Vec<Spec>> = Lazy::new(|| vec![\n{full_32_instrs_by_opcode[opcode]}]);\n'
        )
        full_32_opcode_sections += "\n"

    full_64_opcode_sections = ""
    for opcode in sorted(full_64_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        full_64_opcode_sections += (
            f'pub static RV_ISA_SPECS_64_FULL_OPCODE_{opcode_str}: '
            f'Lazy<Vec<Spec>> = Lazy::new(|| vec![\n{full_64_instrs_by_opcode[opcode]}]);\n'
        )
        full_64_opcode_sections += "\n"

    # Build lookup functions for the API
    generic_lookup_entries = ""
    for opcode in sorted(full_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        generic_lookup_entries += f"        {hex(opcode)} => Some(&RV_ISA_SPECS_GENERIC_FULL_OPCODE_{opcode_str}),\n"

    xlen_32_lookup_entries = ""
    for opcode in sorted(full_32_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        xlen_32_lookup_entries += f"        {hex(opcode)} => Some(&RV_ISA_SPECS_32_FULL_OPCODE_{opcode_str}),\n"

    xlen_64_lookup_entries = ""
    for opcode in sorted(full_64_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        xlen_64_lookup_entries += f"        {hex(opcode)} => Some(&RV_ISA_SPECS_64_FULL_OPCODE_{opcode_str}),\n"

        # Build the lookup API
    lookup_api = f"""
// Opcode lookup API - dynamically generated lookup functions

/// Get generic full instruction specs by opcode
pub fn get_generic_full_specs_by_opcode(opcode: u8) -> Option<&'static Lazy<Vec<Spec>>> {{
    match opcode {{
{generic_lookup_entries}        _ => None,
    }}
}}

/// Get 32-bit specific full instruction specs by opcode
pub fn get_32_full_specs_by_opcode(opcode: u8) -> Option<&'static Lazy<Vec<Spec>>> {{
    match opcode {{
{xlen_32_lookup_entries}        _ => None,
    }}
}}

/// Get 64-bit specific full instruction specs by opcode
pub fn get_64_full_specs_by_opcode(opcode: u8) -> Option<&'static Lazy<Vec<Spec>>> {{
    match opcode {{
{xlen_64_lookup_entries}        _ => None,
    }}
}}
"""

    with open("isa.rs", "w", encoding="utf-8") as rust_file:
        rust_file.write(
            f"""/* Automatically generated by parse_opcodes */
use once_cell::sync::Lazy;
use crate::args::*;

#[derive(Debug, Clone)]
pub struct Spec {{
  pub name: String,
  pub mask_bits: u32,
  pub match_bits: u32,
  pub args: Vec<fn(u32)->(Arg, String)>,
}}

impl Spec {{    
    pub fn new(name: &str, mask_bits: u32, match_bits: u32, args: Vec<fn(u32)->(Arg, String)>) -> Self {{
        Self {{ name: name.to_string(), mask_bits, match_bits, args }}
    }}

    pub fn compare(&self, code: u32) -> bool {{
        (code & self.mask_bits) == self.match_bits
    }}
}}

// Compressed instructions (16-bit) - general (not XLEN-specific)
pub static RV_ISA_SPECS_GENERIC_COMPRESSED: Lazy<Vec<Spec>> = Lazy::new(|| vec![
{compressed_instrs}]);

// Compressed instructions (16-bit) - 32-bit specific
pub static RV_ISA_SPECS_32_COMPRESSED: Lazy<Vec<Spec>> = Lazy::new(|| vec![
{compressed_32_instrs}]);

// Compressed instructions (16-bit) - 64-bit specific
pub static RV_ISA_SPECS_64_COMPRESSED: Lazy<Vec<Spec>> = Lazy::new(|| vec![
{compressed_64_instrs}]);

// Full instructions (32-bit) - general (not XLEN-specific) grouped by opcode
{full_opcode_sections}
// Full instructions (32-bit) - 32-bit specific grouped by opcode
{full_32_opcode_sections}
// Full instructions (32-bit) - 64-bit specific grouped by opcode
{full_64_opcode_sections}

{lookup_api}
"""
        )

    const_str = ""
    for num, name in csrs + csrs32:
        const_str += f"const CSR_{name.upper()}: u16 = {hex(num)};\n"
    for num, name in causes:
        const_str += (
            f'const CAUSE_{name.upper().replace(" ","_")}: u8 = {hex(num)};\n'
        )
    with open("isa_consts.rs", "w", encoding="utf-8") as rust_file:
        rust_file.write(
            f"""/* Automatically generated by parse_opcodes */
{const_str}
"""
        )

# helper function to split shared arguments
def canonicalize_arg(v: str) -> list[str]:
    if v == "rd_rs1_p":
        return ["rd_p", "rs1_p"]
    elif v == "rd_rs1_n0":
        return ["rd_n0", "rs1_n0"]
    else:
        return [v]

