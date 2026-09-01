use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind, RelocationTarget, RelocationFlags};
use petgraph::{dot::{Config, Dot}, graph::{DiGraph, NodeIndex}};
use std::{collections::HashMap, fs};

#[derive(Debug)]
struct Function {
    name:       String,
    address:    u64,
    size:       u64,  
}

fn read_plt_slots(file: &object::File) -> HashMap<u64, String> {
    let mut slots: HashMap<u64, String> = HashMap::new();

    let mut dynindex_to_name: HashMap<usize, String> = HashMap::new();
    for symbol in file.dynamic_symbols() {
        if let Ok(name) = symbol.name() {
            if !name.is_empty() {
                dynindex_to_name.insert(symbol.index().0, name.to_string());
            }
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

        if let RelocationTarget::Symbol(sym_index) = reloc.target() {
            if let Some(name) = dynindex_to_name.get(&sym_index.0) {
                slots.insert(address, name.clone());
            }
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
            Mnemonic::Jmp => {
                if instr.op0_kind() == OpKind::Memory {
                    let slot = instr.memory_displacement64();
                    stubs.insert(current_stub_start,slot);
                }
            }
            _ => {}
        }
    }
    stubs
}
fn main() {
    let path = "test/test_target";
    let bytes = fs::read(path).expect("can't read file");
    let file = object::File::parse(&*bytes).expect("can't parse as object file");

    let plt_slots = read_plt_slots(&file);

    let plt_stubs = read_plt_stubs(&file);

    let mut plt_names: HashMap<u64, String> = HashMap::new();
    for (stub_addr, slot_addr) in &plt_stubs{
        if let Some(name) = plt_slots.get(slot_addr) {
            plt_names.insert(*stub_addr, name.clone());           
        }
    }

    println!("PLT-stubs (stub address -> name):");
    for (addr, name) in &plt_names {
        println!("  {:#x} -> {}", addr, name);
    }

    println!("PLT-slots (slot address -> name):");
    for (addr, name) in &plt_slots {
        println!("  {:#x} -> {}", addr, name);
    }

    let text = file.section_by_name(".text").expect("no section .text");
    let text_addr = text.address();
    let text_end = text_addr + text.size();

    let mut functions: Vec<Function> = Vec::new();

    for symbol in file.symbols() {
        if symbol.kind() == SymbolKind::Text && symbol.address() != 0 {
            functions.push(Function { 
                name: symbol.name().unwrap_or("<unkhown>").to_string(), 
                address: symbol.address(),  
                size: symbol.size() 
            });
        }
    }

    functions.sort_by_key(|f| f.address);

    let mut addr_to_name: HashMap<u64, String> = HashMap::new();
    for f in &functions {
        addr_to_name.insert(f.address, f.name.clone());
    }

    let mut graph : DiGraph<String, ()> = DiGraph::new();

    let mut node_index: HashMap<String, NodeIndex> = HashMap::new();

    let get_or_add = |graph: &mut DiGraph<String, ()>,
                                                                node_index: &mut HashMap<String, NodeIndex>,
                                                                name: &str|
    -> NodeIndex {
        if let Some(&idx) = node_index.get(name) {
            idx
        }
        else {
            let idx = graph.add_node(name.to_string());
            node_index.insert(name.to_string(), idx);
            idx
        }
    };

    for f in &functions {
        if f.size == 0 || f.address < text_addr || f.address + f.size > text_end {
            continue;
        }

        let code = text
            .data_range(f.address, f.size)
            .expect("data_range returned an error")
            .expect("range out of section");

        println!("\n{} @ {:#x}", f.name, f.address);

        let mut decoder = Decoder::with_ip(64, code, f.address, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            if instr.mnemonic() == Mnemonic::Call && instr.op0_kind() == OpKind::NearBranch64 {
                let target = instr.near_branch_target();
                let callee_name = if let Some(name) = addr_to_name.get(&target) {
                    name.clone()
                } else if let Some(name) = plt_names.get(&target) {
                    name.clone()
                } else {
                    format!("sub_{:x}", target)
                };
                let caller_idx = get_or_add(&mut graph, &mut node_index, &f.name);
                let callee_idx = get_or_add(&mut graph, &mut node_index, &callee_name);

                graph.add_edge(caller_idx, callee_idx, ());

            }
        }
    }

    println!("Graph: {} nodes, {} edges", graph.node_count(), graph.edge_count());

let dot = Dot::with_attr_getters(
    &graph,
    &[Config::EdgeNoLabel, Config::NodeNoLabel],
    &|_graph, _edge| String::new(),
    &|_graph, node| format!("label = \"{}\"", node.1),
);
let dot_string = format!("{:?}", dot);

    fs::write("callgraph.dot", &dot_string).expect("can't saved to callgraph.dot");
    println!("DOT saved to callgraph.dot");

}