mod binary;
mod callgraph;
mod server;
mod trace;

use callgraph::{CallGraph, NodeKind};
use clap::Parser;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use trace::{Engine, InputSpec, Target, TraceResult};

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

    /// Run the binary after the analysis and list the functions that executed
    #[arg(long)]
    run: bool,

    /// Tracing engine for --run: ptrace or valgrind
    #[arg(long, default_value = "ptrace")]
    engine: String,

    /// File whose content goes to the binary's stdin under --run
    #[arg(long)]
    stdin: Option<String>,

    /// Arguments for the binary under --run, after "--"
    #[arg(last = true, value_name = "ARGS")]
    run_args: Vec<String>,
}

#[derive(Serialize)]
struct Report<'a> {
    binary: &'a str,
    info: &'a binary::BinaryInfo,
    functions: &'a [binary::Function],
    graph: callgraph::GraphExport,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<&'a TraceResult>,
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

    let export = graph.export();
    let target = Target::new(
        path.clone(),
        info.entry_point,
        &functions,
        &plt_names,
        &export.nodes,
    );
    let trace = args.run.then(|| run_target(&args, &target));
    if let Some(trace) = &trace {
        print_trace(trace, &args.engine, &export.nodes);
    }

    let dot = graph.to_dot();
    fs::write(&args.output, &dot).expect("can't write dot file");
    println!("DOT saved to {}", args.output);

    if let Some(json_path) = &args.json {
        let report = Report {
            binary: path,
            info: &info,
            functions: &functions,
            graph: graph.export(),
            trace: trace.as_ref(),
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
            trace: None,
        };
        let report_json = serde_json::to_string(&report).expect("can't serialize report");
        let state =
            server::AppState::new(path.clone(), info, functions, target, export, report_json);
        server::serve(state, port).await;
    }
}

fn run_target(args: &Args, target: &Target) -> TraceResult {
    let Some(engine) = Engine::parse(&args.engine) else {
        eprintln!("unknown engine: {}", args.engine);
        std::process::exit(2);
    };
    let stdin = args.stdin.as_ref().map(|file| {
        String::from_utf8_lossy(&fs::read(file).expect("can't read stdin file")).into_owned()
    });
    let input = InputSpec {
        stdin,
        args: args.run_args.clone(),
        input_file: None,
    };
    engine.run(target, &input)
}

fn print_trace(trace: &TraceResult, engine: &str, nodes: &[callgraph::Node]) {
    let outcome = match (&trace.error, trace.exit_code) {
        (Some(error), _) => error.clone(),
        (None, Some(code)) => format!("exit code {}", code),
        (None, None) => "no exit code".to_string(),
    };
    println!("Trace ({}): {}", engine, outcome);

    let mut by_hits: Vec<(&str, u64)> = trace
        .node_hits
        .iter()
        .map(|(&id, &hits)| (nodes[id].name.as_str(), hits))
        .collect();
    by_hits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    println!("  {:<24} {:>10}", "NAME", "HITS");
    for (name, hits) in by_hits {
        println!("  {:<24} {:>10}", name, hits);
    }
    println!(
        "  executed: {} nodes, {} edges",
        trace.executed_nodes.len(),
        trace.executed_edges.len()
    );
}
