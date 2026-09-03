mod binary;
mod callgraph;
mod server;

use callgraph::{CallGraph, NodeKind};
use clap::Parser;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;

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

    /// Write full analysis as JSON to this path
    #[arg(long)]
    json: Option<String>,

    /// Serve results over HTTP on this port instead of writing files
    #[arg(long)]
    serve: Option<u16>,
}

#[derive(Serialize)]
struct Report<'a> {
    binary: &'a str,
    info: &'a binary::BinaryInfo,
    functions: &'a [binary::Function],
    graph: callgraph::GraphExport,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let path = &args.binary;

    let bytes = fs::read(path).expect("can't read file");
    let file = object::File::parse(&*bytes).expect("can't parse as object file");

    let info = binary::load_info(&file, &bytes);
    let mut functions = binary::load_functions(&file);
    let plt_names = binary::resolve_plt(&file);
    let by_addr = binary::index_by_address(&functions);
    let calls = binary::analyze_functions(&file, &mut functions);

    let mut calls_in: HashMap<u64, u32> = HashMap::new();
    for (_, target) in &calls {
        *calls_in.entry(*target).or_insert(0) += 1;
    }

    let mut graph = CallGraph::new();
    for (caller_addr, target) in &calls {
        let caller_name = match by_addr.get(caller_addr) {
            Some(n) => n.clone(),
            None => continue,
        };
        let (callee_name, callee_kind) = binary::resolve_target(*target, &by_addr, &plt_names);
        graph.add_call(&caller_name, NodeKind::Local, &callee_name, callee_kind);
    }

    if !args.no_info {
        println!("=== {} ===", path);
        print!("{}", info);
    }

    let mut by_calls_in: Vec<&binary::Function> = functions.iter().collect();
    by_calls_in.sort_by_key(|f| std::cmp::Reverse(calls_in.get(&f.address).copied().unwrap_or(0)));

    println!("Functions:");
    println!(
        "  {:<24} {:>10} {:>6} {:>7} {:>5} {:>5}",
        "NAME", "ADDR", "SIZE", "INSTRS", "IN", "OUT"
    );
    for f in &by_calls_in {
        let inc = calls_in.get(&f.address).copied().unwrap_or(0);
        println!(
            "  {:<24} {:#010x} {:>6} {:>7} {:>5} {:>5}",
            f.name, f.address, f.size, f.instructions, inc, f.calls_out
        );
    }

    println!("Binary: {}", path);
    println!("  functions:    {}", functions.len());
    println!("  plt entries:  {}", plt_names.len());
    println!("  direct calls: {}", calls.len());
    println!(
        "Graph: {} nodes, {} edges",
        graph.node_count(),
        graph.edge_count()
    );

    let dot = graph.to_dot();
    fs::write(&args.output, &dot).expect("can't write dot file");
    println!("DOT saved to {}", args.output);

    if let Some(json_path) = &args.json {
        let report = Report {
            binary: path,
            info: &info,
            functions: &functions,
            graph: graph.export(),
        };
        let json = serde_json::to_string_pretty(&report).expect("can't serialize report");
        fs::write(json_path, json).expect("can't write json");
        println!("JSON saved to {}", json_path);
    }

    if let Some(port) = args.serve {
        let report = Report {
            binary: path,
            info: &info,
            functions: &functions,
            graph: graph.export(),
        };
        let report_json = serde_json::to_string(&report).expect("can't serialize report");
        let state =
            server::AppState::new(path.clone(), info, functions, graph.export(), report_json);
        server::serve(state, port).await;
    }
}
