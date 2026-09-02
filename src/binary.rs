use crate::callgraph::NodeKind;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use object::{Object, ObjectKind, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SymbolKind, Endianness, {read::elf::{ElfFile, ProgramHeader}}, {elf::{FileHeader64, PT_GNU_RELRO, PT_GNU_STACK, PF_X}}};
use std::{collections::HashMap, fmt};

type Elf64<'a> = ElfFile<'a, FileHeader64<Endianness>>;

#[derive(Debug)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub instructions: u32,
    pub calls_out: u32,
}
#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct BinaryInfo {
    pub format: String,
    pub architecture: String,
    pub bits: u8,
    pub endianness: String,
    pub kind: String,
    pub entry_point: u64,
    pub interpreter: Option<String>,
    pub compiler: Vec<String>,  
    pub needed_libs: Vec<String>,
    pub stripped: bool,
    pub instrumentation: Vec<Detection>,
    pub sections: Vec<SectionInfo>,
    pub hardening: Option<Hardening>,
}

#[derive(Debug)]
pub struct Detection {
    pub name: String,          
    pub symbols: Vec<String>,  
    pub linked_lib: Option<String>, 
}

#[derive(Debug)]
pub struct Hardening {
    pub nx: bool,
    pub relro: String,
    pub canary: bool,
    pub cet: bool,
    pub fortify: bool,
    pub pie: bool,
}

pub fn load_functions(file: &object::File) -> Vec<Function> {
    let mut functions = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() == SymbolKind::Text && symbol.address() != 0 {
            functions.push(Function {
                name: symbol.name().unwrap_or("<unknown>").to_string(),
                address: symbol.address(),
                size: symbol.size(),
                instructions: 0,
                calls_out: 0,
            });
        }
    }
    functions.sort_by_key(|f| f.address);
    functions
}

pub fn index_by_address(functions: &[Function]) -> HashMap<u64, String> {
    functions
        .iter()
        .map(|f| (f.address, f.name.clone()))
        .collect()
}


pub fn resolve_plt(file: &object::File) -> HashMap<u64, String> {
    let slots = read_plt_slots(file);
    let stubs = read_plt_stubs(file);

    let mut names = HashMap::new();
    for (stub_addr, slot_addr) in &stubs {
        if let Some(name) = slots.get(slot_addr) {
            names.insert(*stub_addr, name.clone());
        }
    }
    names
}

fn read_plt_slots(file: &object::File) -> HashMap<u64, String> {
    let mut slots: HashMap<u64, String> = HashMap::new();

    let mut dynindex_to_name: HashMap<usize, String> = HashMap::new();
    for symbol in file.dynamic_symbols() {
        if let Ok(name) = symbol.name() && !name.is_empty() {
            dynindex_to_name.insert(symbol.index().0, name.to_string());
        }
    }

    let relocations = match file.dynamic_relocations() {
        Some(iter) => iter,
        None => return slots,
    };

    for (address, reloc) in relocations {
        let is_jump_slot = match reloc.flags() {
            RelocationFlags::Elf { r_type } => r_type == object::elf::R_X86_64_JUMP_SLOT,
            _ => false,
        };
        if !is_jump_slot {
            continue;
        }

        if let RelocationTarget::Symbol(sym_index) = reloc.target() && let Some(name) = dynindex_to_name.get(&sym_index.0) {
            slots.insert(address, name.clone());
        }
    }

    slots
}

fn read_plt_stubs(file: &object::File) -> HashMap<u64, u64> {
    let mut stubs: HashMap<u64, u64> = HashMap::new();

    let section = match file.section_by_name(".plt.sec") {
        Some(s) => s,
        None => return stubs,
    };

    let sec_addr = section.address();
    let data = match section.data() {
        Ok(d) => d,
        Err(_) => return stubs,
    };

    let mut decoder = Decoder::with_ip(64, data, sec_addr, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut current_stub_start = sec_addr;

    while decoder.can_decode() {
        let ip_before = decoder.ip();
        decoder.decode_out(&mut instr);
        match instr.mnemonic() {
            Mnemonic::Endbr64 => {
                current_stub_start = ip_before;
            }
        Mnemonic::Jmp if instr.op0_kind() == OpKind::Memory => {
            stubs.insert(current_stub_start, instr.memory_displacement64());
        }
            _ => {}
        }
    }
    stubs
}

pub fn resolve_target(
    target: u64,
    functions_by_addr: &HashMap<u64, String>,
    plt_names: &HashMap<u64, String>,
) -> (String, NodeKind) {
    if let Some(name) = functions_by_addr.get(&target) {
        (name.clone(), NodeKind::Local)
    } else if let Some(name) = plt_names.get(&target) {
        (name.clone(), NodeKind::Plt)
    } else {
        (format!("sub_{:x}", target), NodeKind::Unknown)
    }
}

pub fn load_info(file: &object::File, raw: &[u8]) -> BinaryInfo {
    let interpreter = file
        .section_by_name(".interp")
        .and_then(|s| s.data().ok())
        .map(|d| String::from_utf8_lossy(d).trim_end_matches('\0').to_string());

    let sections = file
        .sections()
        .map(|s| SectionInfo {
            name: s.name().unwrap_or("<unnamed>").to_string(),
            address: s.address(),
            size: s.size(),
        })
        .collect();

    let compiler = read_compiler_info(file);
    let needed_libs = read_needed_libs(file);
    let instrumentation = detect_instrumentation(file, &needed_libs);
    let stripped = file.symbols().next().is_none();
    let hardening = check_hardening(file, raw);

    BinaryInfo {
        format: format!("{:?}", file.format()),
        architecture: format!("{:?}", file.architecture()),
        bits: if file.is_64() { 64 } else { 32 },
        endianness: format!("{:?}", file.endianness()),
        kind: format!("{:?}", file.kind()),
        entry_point: file.entry(),
        interpreter,
        compiler,
        needed_libs,
        instrumentation,
        stripped,
        sections,
        hardening,
    }
}

impl fmt::Display for BinaryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Format:      {} ({}-bit, {} endian)",
            self.format, self.bits, self.endianness
        )?;
        writeln!(f, "Arch:        {}", self.architecture)?;
        writeln!(f, "Kind:        {}", self.kind)?;
        writeln!(f, "Entry point: {:#x}", self.entry_point)?;
        if let Some(interp) = &self.interpreter {
            writeln!(f, "Interpreter: {}", interp)?;
        }

        if !self.compiler.is_empty() {
            writeln!(f, "Compiler:    {}", self.compiler.join("; "))?;
        }
        writeln!(
            f,
            "Symbols:     {}",
            if self.stripped { "stripped" } else { "present (.symtab)" }
        )?;
        if !self.needed_libs.is_empty() {
            writeln!(f, "Needed libs:")?;
            for lib in &self.needed_libs {
                writeln!(f, "  {}", lib)?;
            }
        }

        if self.instrumentation.is_empty() {
            writeln!(f, "Instrumentation: none detected")?;
        } else {
            writeln!(f, "Instrumentation:")?;
            for det in &self.instrumentation {
                write!(f, "  {}", det.name)?;
                if let Some(lib) = &det.linked_lib {
                    write!(f, "  [linked: {}]", lib)?;
                }
                writeln!(f)?;
                if !det.symbols.is_empty() {
                    writeln!(f, "    evidence: {}", det.symbols.join(", "))?;
                }
            }
        }

        if let Some(h) = &self.hardening {
            writeln!(f, "Hardening:")?;
            writeln!(f, "  NX:      {}", if h.nx { "enabled" } else { "DISABLED" })?;
            writeln!(f, "  RELRO:   {}", h.relro)?;
            writeln!(f, "  Canary:  {}", if h.canary { "found" } else { "not found" })?;
            writeln!(f, "  CET:     {}", if h.cet { "property note present" } else { "no" })?;
            writeln!(f, "  Fortify: {}", if h.fortify { "found" } else { "not found" })?;
            writeln!(f, "  PIE:     {}", if h.pie { "yes" } else { "no" })?;
        }

        writeln!(f, "Sections ({}):", self.sections.len())?;
        for s in &self.sections {
            writeln!(f, "  {:<20} {:#010x}  {:>8}", s.name, s.address, s.size)?;
        }
        Ok(())
    }
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let rest = &data[offset..];
    let end = rest.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..end]).to_string())
}

fn read_compiler_info(file: &object::File) -> Vec<String> {
    let Some(section) = file.section_by_name(".comment") else {
        return Vec::new();
    };
    let Ok(data) = section.data() else {
        return Vec::new();
    };

    let mut comments: Vec<String> = data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();
    comments.sort();
    comments.dedup();
    comments
}

fn read_needed_libs(file: &object::File) -> Vec<String> {
    let Some(dynstr) = file.section_by_name(".dynstr") else {
        return Vec::new();
    };
    let Ok(str_data) = dynstr.data() else {
        return Vec::new();
    };

    dynamic_entries(file)
        .filter(|&(tag, _)| tag == object::elf::DT_NEEDED as u64)
        .filter_map(|(_, val)| read_cstr(str_data, val as usize))
        .collect()
}

pub fn detect_instrumentation(file: &object::File, needed_libs: &[String]) -> Vec<Detection> {
    const SIGNATURES: &[(&str, &[&str], Option<&str>)] = &[
        ("AddressSanitizer", &["__asan_"], Some("libasan")),
        ("ThreadSanitizer", &["__tsan_"], Some("libtsan")),
        ("MemorySanitizer", &["__msan_"], Some("libmsan")),
        ("UBSanitizer", &["__ubsan_"], Some("libubsan")),
        ("LeakSanitizer", &["__lsan_"], Some("liblsan")),
        ("SanitizerCoverage", &["__sanitizer_cov_"], None),
        ("libFuzzer", &["LLVMFuzzerTestOneInput"], None),
        ("AFL", &["__afl_"], None),
        ("gcov/profiling", &["__gcov_", "__llvm_profile_"], None),
    ];

    let all_symbols: Vec<String> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|s| s.name().ok())
        .filter(|n| !n.is_empty())
        .map(|n| n.to_string())
        .collect();

    let mut detections = Vec::new();

    for (name, prefixes, lib_hint) in SIGNATURES {
        let mut hits: Vec<String> = all_symbols
            .iter()
            .filter(|sym| prefixes.iter().any(|p| sym.starts_with(p) || sym == p))
            .cloned()
            .collect();
        hits.sort();
        hits.dedup();

        let linked_lib = lib_hint.and_then(|hint| {
            needed_libs
                .iter()
                .find(|lib| lib.contains(hint))
                .cloned()
        });

        if !hits.is_empty() || linked_lib.is_some() {
            hits.truncate(5); 
            detections.push(Detection {
                name: name.to_string(),
                symbols: hits,
                linked_lib,
            });
        }
    }

    detections
}

pub fn check_hardening(file: &object::File, raw: &[u8]) -> Option<Hardening> {
    let elf: Elf64 = Elf64::parse(raw).ok()?;
    let endian = elf.endian();

    let mut nx = true; 
    let mut has_relro_segment = false;

    for ph in elf.elf_program_headers() {
        let p_type = ph.p_type(endian);
        if p_type == PT_GNU_STACK {
            nx = ph.p_flags(endian) & PF_X == 0;
        }
        if p_type == PT_GNU_RELRO {
            has_relro_segment = true;
        }
    }

    let bind_now: bool = has_dynamic_flag(file, object::elf::DT_BIND_NOW as u64)
        || has_dynamic_flag_value(file, object::elf::DT_FLAGS as u64, object::elf::DF_BIND_NOW as u64);
    let relro = match (has_relro_segment, bind_now) {
        (true, true) => "full",
        (true, false) => "partial",
        _ => "none",
    }
    .to_string();

    let mut canary = false;
    let mut fortify = false;
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(name) = sym.name() {
            if name == "__stack_chk_fail" {
                canary = true;
            }
            if name.ends_with("_chk") && name.starts_with("__") && name != "__stack_chk_fail" {
                fortify = true;
            }
        }
    }

    let cet = file.section_by_name(".note.gnu.property").is_some();

    let pie = file.kind() == ObjectKind::Dynamic;

    Some(Hardening { nx, relro, canary, cet, fortify, pie })
}

fn has_dynamic_flag(file: &object::File, wanted_tag: u64) -> bool {
    dynamic_entries(file).any(|(tag, _)| tag == wanted_tag)
}

fn has_dynamic_flag_value(file: &object::File, wanted_tag: u64, bit: u64) -> bool {
    dynamic_entries(file).any(|(tag, val)| tag == wanted_tag && val & bit != 0)
}

fn dynamic_entries<'a>(file: &'a object::File) -> impl Iterator<Item = (u64, u64)> + 'a {
    file.section_by_name(".dynamic")
        .and_then(|s| s.data().ok())
        .unwrap_or(&[])
        .chunks_exact(16)
        .map(|e| {
            (
                u64::from_le_bytes(e[0..8].try_into().unwrap()),
                u64::from_le_bytes(e[8..16].try_into().unwrap()),
            )
        })
        .take_while(|&(tag, _)| tag != object::elf::DT_NULL as u64)
}

pub fn analyze_functions(file: &object::File, functions: &mut [Function]) -> Vec<(u64, u64)> {
    let mut calls = Vec::new();

    let text = match file.section_by_name(".text") {
        Some(t) => t,
        None => return calls,
    };
    let text_addr = text.address();
    let text_end = text_addr + text.size();

    for f in functions.iter_mut() {
        if f.size == 0 || f.address < text_addr || f.address + f.size > text_end {
            continue;
        }

        let code = match text.data_range(f.address, f.size) {
            Ok(Some(d)) => d,
            _ => continue,
        };

        let mut decoder = Decoder::with_ip(64, code, f.address, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            f.instructions += 1;

            if instr.mnemonic() == Mnemonic::Call && instr.op0_kind() == OpKind::NearBranch64 {
                f.calls_out += 1;
                calls.push((f.address, instr.near_branch_target()));
            }
        }
    }
    calls
}