mod binary;
mod callgraph;

use callgraph::{CallGraph, NodeKind};
use std::fs;
use clap::Parser;

/// Builds a function call graph from an ELF binary.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the binary to analyze
    binary: String,

    /// Where to write the DOT graph file
    #[arg(short, long, default_value = "callgraph.dot")]
    output: String,

    /// Skip the binary info passport (print only graph and stats)
    #[arg(long)]
    no_info: bool,
}

fn main() {
    let args =Args::parse();
    let path = &args.binary;

    let bytes = fs::read(path).expect("can't read file");
    let file = object::File::parse(&*bytes).expect("can't parse as object file");

    let info = binary::load_info(&file, &bytes);    
    if !args.no_info {
        println!("=== {} ===", path);
        print!("{}", info);
    }

    let functions = binary::load_functions(&file);
    let plt_names = binary::resolve_plt(&file);
    let by_addr = binary::index_by_address(&functions);
    let calls = binary::extract_calls(&file, &functions);

    let mut graph = CallGraph::new();
    for (caller_addr, target) in &calls {
        let caller_name = match by_addr.get(caller_addr) {
            Some(n) => n.clone(),
            None => continue,
        };
        let (callee_name, callee_kind) = binary::resolve_target(*target, &by_addr, &plt_names);
        graph.add_call(&caller_name, NodeKind::Local, &callee_name, callee_kind);
    }

    println!("Binary: {}", path);
    println!("  functions:    {}", functions.len());
    println!("  plt entries:  {}", plt_names.len());
    println!("  direct calls: {}", calls.len());
    println!("Graph: {} nodes, {} edges", graph.node_count(), graph.edge_count());

    let dot = graph.to_dot();
    fs::write(&args.output, &dot).expect("can't write callgraph.dot");
    println!("DOT saved to callgraph.dot");
}