use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use petgraph::{dot::{Config, Dot}, graph::{DiGraph, NodeIndex}};
use std::{collections::HashMap, fs};

#[derive(Debug)]
struct Function {
    name:       String,
    address:    u64,
    size:       u64,  
}

fn main() {
    let path = "test/test_target";
    let bytes = fs::read(path).expect("can't read file");
    let file = object::File::parse(&*bytes).expect("can't parse as object file");

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
                let callee_name = match addr_to_name.get(&target) {
                    Some(name) => name.clone(),
                    None => format!("sub_{:x}", target),
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