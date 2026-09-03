# binary2graph

binary2graph builds a static call graph from an x86-64 ELF binary. It reads the
symbol table, decodes every function body it can reach and records the direct
calls it finds, resolving PLT stubs back to the names of the imported functions.
It also prints a passport of the binary: compiler, dependencies, sanitizer
instrumentation and a hardening checklist.

## Build

`cargo build --release`, which puts the binary in `target/release/binary2graph`.

## Usage

```
Usage: binary2graph [OPTIONS] <BINARY>

Options:
  -o, --output <OUTPUT>  Where to write the DOT graph file [default: callgraph.dot]
      --no-info          Skip the binary info passport (print only graph and stats)
      --json <JSON>      Write full analysis as JSON to this path
      --serve <SERVE>    Serve results over HTTP on this port instead of writing files
```

```
gcc -no-pie -o test/test_target test/test_target.c
gcc -no-pie -o test/test_calc test/test_calc.c
binary2graph test/test_target
binary2graph test/test_calc --no-info -o app.dot --json app.json
binary2graph test/test_calc --serve 8080
```

The DOT file renders with graphviz: `dot -Tsvg callgraph.dot -o callgraph.svg`.

## Output

The passport comes first, then a function table sorted by incoming call count
(address, size, instructions, IN, OUT), then the totals:

```
=== test/test_target ===
Format:      Elf (64-bit, Little endian)
Arch:        X86_64
Kind:        Executable
Entry point: 0x401050
Interpreter: /lib64/ld-linux-x86-64.so.2
Compiler:    GCC: (Ubuntu 14.2.0-19ubuntu2) 14.2.0
Symbols:     present (.symtab)
Needed libs:
  libc.so.6
Instrumentation: none detected
Hardening:
  NX:      enabled
  RELRO:   partial
  Canary:  not found
  CET:     property note present
  Fortify: not found
  PIE:     no
[...]
Graph: 5 nodes, 5 edges
```

## Web UI

`--serve <port>` starts an HTTP server on `127.0.0.1` and keeps it in the
foreground; the DOT file is written as usual before it comes up. `/` is a single
page that draws the graph with cytoscape.js and dagre from CDNs, so the browser
needs network access. Local functions are blue ellipses, PLT stubs orange
rectangles, unresolved targets grey.

Graphs up to 300 nodes are drawn whole. Bigger ones open as an explorer: the
scene starts at `main` (or the entry point) and a click on a node adds its
direct callers and callees; a `+` after a name marks neighbours not on screen
yet. The panel has a substring search over every function, root lists (entry
point, exported functions, most called) that restart the scene from a new seed,
and for the selected node its address, size, instruction count, in/out counts
and clickable caller and callee lists. The toolbar hides PLT stubs, collapses
PLT and unknown nodes into one `external` node, hides nodes below a degree,
relays the scene and keeps a breadcrumb trail of seeds. One click brings in at
most 200 neighbours and the scene holds at most 500 nodes; the status line says
when either cut applies.

![binary2graph web UI](docs/webui.png)

## Running the target

The `run` box in the panel executes the analysed binary and draws what ran on
top of the static graph. Pick an engine, type stdin and arguments, attach an
input file if the program reads one (`@@` among the arguments stands for its
path, otherwise the path goes last) and press `run`. Executed functions get a
green border and a `×N` call count, executed edges turn green with their own
count, and the node details show `hits`. The `trace` toggle hides the overlay
and `only executed` cuts the scene down to what ran. In explorer mode the
executed functions are added to the scene first, within the scene limit.

Engines:

- `ptrace` plants a breakpoint on every function entry and PLT stub, reads the
  caller from the return address on each hit and follows threads and forks.
  No dependencies, but a call-heavy program slows down a lot.
- `valgrind` runs `valgrind --tool=callgrind` and reads the call counts from
  the dump, matched to the graph by address. Needs valgrind installed; the
  page says so when it is missing.

Both engines report the same shape: executed nodes and edges with counts, the
exit code or the signal that killed the program, and stdout and stderr cut at
16 KiB each. A run is killed after 10 seconds, and runs are serialised.

`--serve` with a run is code execution: the binary runs as the user who
started the server, with input taken from the page. Serve only binaries you
trust, and prefer a VM or a container for anything else. The server listens on
`127.0.0.1` and takes runs only as `application/json` POSTs, which keeps a
page from another site from starting one.

## HTTP API

- `/api/meta`: passport, function table and every graph node with its in/out
  degree, no edges. Loaded once when the page opens.
- `/api/neighbors?id=N&depth=1&dir=both&budget=200`: breadth-first walk from
  node `N` (`dir` is `out`, `in` or `both`); returns the visited ids with a
  `has_more` flag each, the edges among them and `truncated` when the budget
  stopped the walk.
- `/api/search?q=text`: case-insensitive substring match over function and node
  names, at most 50 matches plus the total count.
- `/api/roots`: node ids of the entry point, exported functions and the ten most
  called local functions.
- `/api/report`: the same report that `--json` writes.
- `POST /api/run`: body `{"engine": "ptrace" | "valgrind", "stdin": text,
  "args": [...], "input_file": base64}`, everything but `engine` optional.
  Returns `executed_nodes`, `executed_edges`, `node_hits` keyed by node id,
  `edge_hits` keyed by `from-to`, `exit_code`, `stdout`, `stderr` and `error`.
  A crash or timeout still returns what ran before it, with `error` set.

## What the passport reports

- Compiler strings from `.comment` and the `DT_NEEDED` libraries from `.dynamic`.
- Instrumentation: AddressSanitizer, ThreadSanitizer, MemorySanitizer,
  UBSanitizer, LeakSanitizer, SanitizerCoverage, libFuzzer, AFL and gcov/LLVM
  profiling, matched by symbol prefix and by linked runtime, with up to five
  matching symbols printed as evidence.
- Hardening: NX, RELRO (none, partial or full), a `__stack_chk_fail` canary, a
  CET property note, fortified libc calls (`__*_chk`) and PIE.
- Entry point, interpreter, whether symbols survived, and the section table.

## Limitations

- x86-64 ELF only. The decoder runs in 64-bit mode and PLT resolution looks for
  `R_X86_64_JUMP_SLOT` relocations.
- Only direct near calls become edges. Calls through a register or memory
  operand, and tail calls compiled to `jmp`, are not resolved.
- Function discovery needs `.symtab`. On a stripped binary the passport still
  works, but the function table and the graph come out empty.
- Functions of zero size, or with a body outside `.text`, are skipped.
- PLT names are read from `.plt.sec`, the layout produced with
  `-fcf-protection`. Without it, calls into the PLT stay as `sub_<address>` nodes.
- Exported functions come from `.dynsym`, so the list is empty for an executable
  built without `-rdynamic`.
- The explorer shows at most 200 neighbours per click; the rest of a hub's
  callers are reachable through search only.
- A run counts calls into functions of the graph only. A callback invoked from
  a library, such as a `qsort` comparator, gets its hits but no edge, and calls
  from an `Unknown` node are never seen.
- Under `ptrace` a tail call keeps the original return address on the stack,
  so the edge is drawn from the function that made the first call, and a
  breakpoint hit in one thread can go unseen while another thread steps over
  the same entry.
- Under `valgrind` the target runs tens of times slower, so a program that
  takes more than a fraction of a second natively hits the 10 second limit.

## How it works

`object` parses the ELF and hands over symbols, sections and dynamic
relocations; `iced-x86` decodes each function body to count instructions and
collect call targets; `petgraph` holds the graph and emits the DOT; `serde_json`
serialises the full report, and `axum` serves it next to the embedded page,
answering neighbourhood queries from adjacency lists built at start-up. A run
maps runtime addresses back to graph nodes through the function ranges and PLT
stub addresses found during analysis; `nix` wraps the ptrace calls, and the
callgrind dump is parsed by the server itself.
