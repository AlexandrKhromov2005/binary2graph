use crate::callgraph::NodeKind;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SymbolKind};
use std::{collections::HashMap, fmt};

#[derive(Debug)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

pub fn load_functions(file: &object::File) -> Vec<Function> {
    let mut functions = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() == SymbolKind::Text && symbol.address() != 0 {
            functions.push(Function {
                name: symbol.name().unwrap_or("<unknown>").to_string(),
                address: symbol.address(),
                size: symbol.size(),
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

pub fn extract_calls(file: &object::File, functions: &[Function]) -> Vec<(u64, u64)> {
    let mut calls = Vec::new();

    let text = match file.section_by_name(".text") {
        Some(t) => t,
        None => return calls,
    };
    let text_addr = text.address();
    let text_end = text_addr + text.size();

    for f in functions {
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
            if instr.mnemonic() == Mnemonic::Call && instr.op0_kind() == OpKind::NearBranch64 {
                calls.push((f.address, instr.near_branch_target()));
            }
        }
    }
    calls
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