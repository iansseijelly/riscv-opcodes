import logging
import os
import pprint
from constants import causes, csrs, csrs32
from shared_utils import InstrDict

pp = pprint.PrettyPrinter(indent=4)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:: %(message)s")


# Pseudo-ops emitted as instructions: the RV32 encodings of instructions whose RV64 encodings differ, under the
# instruction's own name in the RV32 tables; fence.tso; and the defined illegal instructions c.unimp and unimp. Each
# comes first in its table, before an instruction whose encodings include its own.
rust_pseudo_ops = ["slli_rv32", "srli_rv32", "srai_rv32", "c_slli_rv32", "c_srli_rv32", "c_srai_rv32", "fence_tso",
                   "c_unimp", "unimp"]


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

    # One packer per distinct operand list, by name: it decodes all of an instruction's operands at once.
    packers: dict[str, list[str]] = {}

    # The same specs, as (variant, mask, match, packer), for the decoders: by class ("generic", "32", or "64").
    compressed_specs: dict[str, list[DecodeSpec]] = {"generic": [], "32": [], "64": []}
    full_specs: dict[str, list[DecodeSpec]] = {"generic": [], "32": [], "64": []}

    for i in sorted(instr_dict, key=lambda name: name not in rust_pseudo_ops):
        name = rust_mnemonic(i)
        variables: list[str] = []
        for v in instr_dict[i]["variable_fields"]:
            variables.extend(canonicalize_arg(v))

        packer = "pack_" + "_".join(variables) if variables else "pack_none"
        packers[packer] = variables

        # Create the instruction spec string
        instr_spec = (
            f'    Spec::new(Op::{rust_variant(name)}, {instr_dict[i]["mask"]}, '
            f'{instr_dict[i]["match"]}, {packer}),\n'
        )

        # Determine instruction characteristics
        is_compressed = instr_dict[i]["length"] == 16
        is_full = instr_dict[i]["length"] == 32
        is_32_specific = "32" in instr_dict[i]["extension"][0]
        is_64_specific = "64" in instr_dict[i]["extension"][0]

        spec_class = "32" if is_32_specific else "64" if is_64_specific else "generic"
        decode_spec = (rust_variant(name), int(instr_dict[i]["mask"], 16), int(instr_dict[i]["match"], 16), packer)
        (compressed_specs if is_compressed else full_specs)[spec_class].append(decode_spec)

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
            f'&[Spec] = &[\n{full_instrs_by_opcode[opcode]}];\n'
        )
        full_opcode_sections += "\n"

    full_32_opcode_sections = ""
    for opcode in sorted(full_32_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        full_32_opcode_sections += (
            f'pub static RV_ISA_SPECS_32_FULL_OPCODE_{opcode_str}: '
            f'&[Spec] = &[\n{full_32_instrs_by_opcode[opcode]}];\n'
        )
        full_32_opcode_sections += "\n"

    full_64_opcode_sections = ""
    for opcode in sorted(full_64_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        full_64_opcode_sections += (
            f'pub static RV_ISA_SPECS_64_FULL_OPCODE_{opcode_str}: '
            f'&[Spec] = &[\n{full_64_instrs_by_opcode[opcode]}];\n'
        )
        full_64_opcode_sections += "\n"

    # Build lookup functions for the API
    generic_lookup_entries = ""
    for opcode in sorted(full_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        generic_lookup_entries += f"        {hex(opcode)} => Some(RV_ISA_SPECS_GENERIC_FULL_OPCODE_{opcode_str}),\n"

    xlen_32_lookup_entries = ""
    for opcode in sorted(full_32_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        xlen_32_lookup_entries += f"        {hex(opcode)} => Some(RV_ISA_SPECS_32_FULL_OPCODE_{opcode_str}),\n"

    xlen_64_lookup_entries = ""
    for opcode in sorted(full_64_instrs_by_opcode.keys()):
        opcode_str = f"{opcode:02x}".upper()
        xlen_64_lookup_entries += f"        {hex(opcode)} => Some(RV_ISA_SPECS_64_FULL_OPCODE_{opcode_str}),\n"

    # The packers. Each calls its extractors by name, so they inline, and hands the results to `Insn::from_parts`.
    packer_fns = ""
    for packer, variables in sorted(packers.items()):
        calls = ", ".join(f"{v}(raw)" for v in variables)
        packer_fns += (
            f"#[inline(always)]\n"
            f"pub(super) fn {packer}(raw: u32, op: Op, xlen: u8) -> Option<Insn> {{\n"
            f"    Insn::from_parts(raw, op, xlen, [{calls}])\n"
            f"}}\n\n"
        )

    decoders = make_decoders(compressed_specs, full_specs)

    # Build the lookup API
    lookup_api = f"""
// Opcode lookup API - dynamically generated lookup functions

/// Get generic full instruction specs by opcode
pub fn get_generic_full_specs_by_opcode(opcode: u8) -> Option<&'static [Spec]> {{
    match opcode {{
{generic_lookup_entries}        _ => None,
    }}
}}

/// Get 32-bit specific full instruction specs by opcode
pub fn get_32_full_specs_by_opcode(opcode: u8) -> Option<&'static [Spec]> {{
    match opcode {{
{xlen_32_lookup_entries}        _ => None,
    }}
}}

/// Get 64-bit specific full instruction specs by opcode
pub fn get_64_full_specs_by_opcode(opcode: u8) -> Option<&'static [Spec]> {{
    match opcode {{
{xlen_64_lookup_entries}        _ => None,
    }}
}}
"""

    header = "/* Automatically generated by parse_opcodes */\n"
    files = {
        "mod.rs": f"""{header}//! The instruction set, generated from riscv-opcodes: the instructions (`Op`, `Ext`), their encodings (the
//! `Spec` tables), and the decoders built from those.

mod decode;
mod op;
mod pack;
mod spec;

pub use decode::{{decode_compressed_32, decode_compressed_64, decode_full_32, decode_full_64}};
pub use op::{{Ext, Op}};
pub use spec::*;
""",
        "op.rs": f"""{header}
{make_op_enum(instr_dict)}""",
        "pack.rs": f"""{header}//! Operand packers: one per distinct operand list, each decoding all of an instruction's operands at once.

use super::Op;
use crate::args::*;
use crate::insn::Insn;

{packer_fns}""",
        "spec.rs": f"""{header}//! The spec tables: each instruction's encoding, as a mask and a match value, and its packer, in the order a
//! decoder must try them. The decoders in `decode` are built from these; the tables are the reference for them.

use super::pack::*;
use super::Op;
use crate::insn::Insn;

#[derive(Debug, Clone)]
pub struct Spec {{
    pub op: Op,
    pub mask_bits: u32,
    pub match_bits: u32,
    /// Decodes the instruction's operands from an encoding that matches, into the instruction for an XLEN; or
    /// `None` if an operand rules the encoding out (a field that must not be zero, say), for the next matching spec
    /// to try.
    pub pack: fn(u32, Op, u8) -> Option<Insn>,
}}

impl Spec {{
    pub const fn new(
        op: Op,
        mask_bits: u32,
        match_bits: u32,
        pack: fn(u32, Op, u8) -> Option<Insn>,
    ) -> Self {{
        Self {{
            op,
            mask_bits,
            match_bits,
            pack,
        }}
    }}

    /// The instruction's mnemonic.
    pub fn name(&self) -> &'static str {{
        self.op.name()
    }}

    pub fn compare(&self, code: u32) -> bool {{
        (code & self.mask_bits) == self.match_bits
    }}
}}

// Compressed instructions (16-bit) - general (not XLEN-specific)
pub static RV_ISA_SPECS_GENERIC_COMPRESSED: &[Spec] = &[
{compressed_instrs}];

// Compressed instructions (16-bit) - 32-bit specific
pub static RV_ISA_SPECS_32_COMPRESSED: &[Spec] = &[
{compressed_32_instrs}];

// Compressed instructions (16-bit) - 64-bit specific
pub static RV_ISA_SPECS_64_COMPRESSED: &[Spec] = &[
{compressed_64_instrs}];

// Full instructions (32-bit) - general (not XLEN-specific) grouped by opcode
{full_opcode_sections}
// Full instructions (32-bit) - 32-bit specific grouped by opcode
{full_32_opcode_sections}
// Full instructions (32-bit) - 64-bit specific grouped by opcode
{full_64_opcode_sections}
{lookup_api}""",
        "decode.rs": f"""{header}//! The decoders: for each length and XLEN, a match on the key fields, then a match per mask, built from the spec
//! tables so that each picks what a scan of the tables in order would.

use super::pack::*;
use super::Op;
use crate::insn::Insn;

{decoders}""",
    }
    os.makedirs("isa", exist_ok=True)
    for name, text in files.items():
        with open(os.path.join("isa", name), "w", encoding="utf-8") as rust_file:
            rust_file.write(text)

    const_str = ""
    for num, name in csrs + csrs32:
        const_str += f"pub const CSR_{name.upper()}: u16 = {hex(num)};\n"
    const_str += "\n/// The name of a CSR, by number.\npub fn csr_name(csr: u32) -> Option<&'static str> {\n    match csr {\n"
    for num, name in csrs + csrs32:
        const_str += f'        {hex(num)} => Some("{name}"),\n'
    const_str += "        _ => None,\n    }\n}\n"
    for num, name in causes:
        const_str += (
            f'pub const CAUSE_{name.upper().replace(" ","_")}: u8 = {hex(num)};\n'
        )
    with open("isa_consts.rs", "w", encoding="utf-8") as rust_file:
        rust_file.write(
            f"""/* Automatically generated by parse_opcodes */
{const_str}
"""
        )

DecodeSpec = tuple[str, int, int, str]

# The fields every spec of each length includes in its mask, which a decoder dispatches on first: a 32-bit
# instruction's opcode, and a 16-bit one's quadrant and funct3.
FULL_KEY = 0x7F
COMPRESSED_KEY = 0xE003


def make_decoders(compressed_specs: dict[str, list[DecodeSpec]], full_specs: dict[str, list[DecodeSpec]]) -> str:
    """The decoders: for each length and XLEN, a match on the key fields, then, for each key, a match per mask."""
    out = ""
    for xlen in ["32", "64"]:
        for length, specs, key in [
            ("compressed", compressed_specs, COMPRESSED_KEY),
            ("full", full_specs, FULL_KEY),
        ]:
            # The generic specs come before the XLEN's own, as the spec tables order them.
            merged = specs["generic"] + specs[xlen]
            out += make_decoder(f"decode_{length}_{xlen}", xlen, length, merged, key)
    return out


def make_decoder(fn: str, xlen: str, length: str, specs: list[DecodeSpec], key: int) -> str:
    """A decoder for `specs`, in priority order: the first spec that matches and whose packer accepts wins."""
    by_key: dict[int, list[DecodeSpec]] = {}
    for spec in specs:
        _, mask, match, _ = spec
        assert mask & key == key, f"{spec[0]}'s mask {mask:#x} does not include the key fields {key:#x}"
        by_key.setdefault(match & key, []).append(spec)

    bits = 16 if length == "compressed" else 32
    out = (
        f"/// Decodes a {bits}-bit encoding as RV{xlen} does: the instruction, or `None` if it is none. A match on\n"
        f"/// the key fields, `{key:#x}`, picks the specs that could match, which `{fn}_*` then try.\n"
        f"pub fn {fn}(code: u32) -> Option<Insn> {{\n"
        f"    match code & {key:#x} {{\n"
    )
    for k in sorted(by_key):
        out += f"        {k:#x} => {fn}_{k:x}(code),\n"
    out += "        _ => None,\n    }\n}\n\n"
    for k in sorted(by_key):
        out += make_key_decoder(f"{fn}_{k:x}", xlen, by_key[k])
    return out


def make_key_decoder(fn: str, xlen: str, specs: list[DecodeSpec]) -> str:
    """The specs that share key fields, as a sequence of matches, each on one mask: within a match, a spec's match
    value picks it, and specs with the same match value chain, in order.

    The specs keep their priority: a spec goes in the first match on its mask that comes after every match holding an
    earlier spec that can match the same encoding, and in a new match at the end if there is none. Usually a mask needs
    only one match; a mask whose specs interleave in priority with another mask's needs more."""

    def overlap(a: DecodeSpec, b: DecodeSpec) -> bool:
        return (a[2] ^ b[2]) & a[1] & b[1] == 0

    groups: list[tuple[int, list[DecodeSpec]]] = []
    for spec in specs:
        first = max((g + 1 for g, (_, members) in enumerate(groups) if any(overlap(m, spec) for m in members)), default=0)
        # A group with an overlapping spec of the same mask has the same match value: joining it chains after it.
        if first > 0 and groups[first - 1][0] == spec[1]:
            first -= 1
        for g in range(first, len(groups)):
            if groups[g][0] == spec[1]:
                groups[g][1].append(spec)
                break
        else:
            groups.append((spec[1], [spec]))

    out = f"fn {fn}(code: u32) -> Option<Insn> {{\n"
    for mask, members in groups:
        arms: dict[int, list[DecodeSpec]] = {}
        for spec in members:
            arms.setdefault(spec[2], []).append(spec)
        # A mask of every bit leaves the code as it is, which clippy flags.
        scrutinee = "code" if mask == 0xFFFFFFFF else f"code & {mask:#x}"
        out += f"    if let Some(insn) = match {scrutinee} {{\n"
        for match, chain in arms.items():
            calls = [f"{packer}(code, Op::{variant}, {xlen})" for variant, _, _, packer in chain]
            out += f"        {match:#x} => {calls[0]}"
            for call in calls[1:]:
                out += f".or_else(|| {call})"
            out += ",\n"
        out += "        _ => None,\n    } {\n        return Some(insn);\n    }\n"
    out += "    None\n}\n\n"
    return out


def rust_mnemonic(key: str) -> str:
    """An instruction's mnemonic from its riscv-opcodes name: c_addi is c.addi, and slli_rv32 is slli."""
    return key.removesuffix("_rv32").replace("_", ".")


def rust_variant(name: str, sep: str = ".") -> str:
    """A Rust variant name: the mnemonic c.addi is CAddi, and the extension rv64_i (with sep "_") is Rv64I."""
    return "".join(part[:1].upper() + part[1:] for part in name.split(sep))


def make_op_enum(instr_dict: InstrDict) -> str:
    # One Op per mnemonic. A mnemonic with both an instruction and an RV32 pseudo-op (slli and slli_rv32) is one Op,
    # which belongs to the instruction's extension: instructions come first, and the first extension seen is kept.
    exts: dict[str, str] = {}
    for key in sorted(instr_dict, key=lambda k: k in rust_pseudo_ops):
        exts.setdefault(rust_mnemonic(key), instr_dict[key]["extension"][0])
    names = sorted(exts)
    ext_names = sorted(set(exts.values()))

    variants = [rust_variant(n) for n in names]
    ext_variants = [rust_variant(e, "_") for e in ext_names]
    for kind, vs in (("Op", variants), ("Ext", ext_variants)):
        if len(set(vs)) != len(vs):
            raise ValueError(f"two {kind} variants have the same Rust name")

    op_variants = "".join(f"    {v},\n" for v in variants)
    op_all = "".join(f"        Op::{v},\n" for v in variants)
    op_names = "".join(f'            Op::{v} => "{n}",\n' for v, n in zip(variants, names))
    op_exts = "".join(f"            Op::{v} => Some(Ext::{rust_variant(exts[n], '_')}),\n" for v, n in zip(variants, names))
    if "Unknown" in variants:
        raise ValueError("an instruction's Op variant is Unknown, which stands for an undecodable encoding")
    ext_variant_list = "".join(f"    {v},\n" for v in ext_variants)
    ext_all = "".join(f"        Ext::{v},\n" for v in ext_variants)
    ext_name_list = "".join(f'            Ext::{v} => "{n}",\n' for v, n in zip(ext_variants, ext_names))

    return f"""/// An instruction: one per mnemonic, in mnemonic order, and `Unknown` for an encoding that decodes to none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum Op {{
{op_variants}    /// Not an instruction: an encoding that decodes to none, which a disassembly walk passes over.
    Unknown,
}}

impl Op {{
    /// Every instruction, in mnemonic order. `Unknown` is not one.
    pub const ALL: &'static [Op] = &[
{op_all}    ];

    /// The instruction's mnemonic, as riscv-opcodes names it: `add`, `c.addi`, `fence.i`; `unknown` for `Unknown`.
    pub const fn name(self) -> &'static str {{
        match self {{
{op_names}            Op::Unknown => "unknown",
        }}
    }}

    /// The riscv-opcodes extension that defines the instruction, or `None` for `Unknown`. A mnemonic that also has
    /// an RV32 pseudo-op encoding, such as `slli`, belongs to its instruction's extension (`rv64_i`).
    pub const fn ext(self) -> Option<Ext> {{
        match self {{
{op_exts}            Op::Unknown => None,
        }}
    }}
}}

/// A riscv-opcodes extension: the file that defines an instruction, such as `rv_i`, `rv64_i`, or `rv_m`. The RV64
/// additions to an extension are their own, so RV64I is `rv_i` and `rv64_i` together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ext {{
{ext_variant_list}}}

impl Ext {{
    /// Every extension that defines an instruction, in name order.
    pub const ALL: &'static [Ext] = &[
{ext_all}    ];

    /// The extension's riscv-opcodes name, such as `rv64_i`.
    pub const fn name(self) -> &'static str {{
        match self {{
{ext_name_list}        }}
    }}
}}
"""


# helper function to split shared arguments
def canonicalize_arg(v: str) -> list[str]:
    if v == "rd_rs1_p":
        return ["rd_rs1_p", "rs1_p"]
    elif v == "rd_rs1_n0":
        return ["rd_n0", "rs1_n0"]
    elif v == "rd_rs1":
        return ["rd", "c_rs1"]
    else:
        return [v]

