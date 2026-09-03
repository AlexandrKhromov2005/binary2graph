use crate::binary::Function;
use nix::errno::Errno;
use nix::libc::{AT_ENTRY, c_long};
use nix::sys::ptrace::{self, AddressType, Options};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Serialize)]
pub struct TraceResult {
    pub executed_nodes: Vec<usize>,
    pub executed_edges: Vec<(usize, usize)>,
    pub node_hits: HashMap<usize, u64>,
    #[serde(serialize_with = "edge_keys")]
    pub edge_hits: HashMap<(usize, usize), u64>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

pub struct InputSpec {
    pub stdin: Option<String>,
    pub args: Vec<String>,
    pub input_file: Option<Vec<u8>>,
}

pub struct Target {
    pub path: String,
    pub args: Vec<String>,
    pub entry_point: u64,
    pub symbols: Symbols,
    pub timeout: Duration,
}

struct Range {
    start: u64,
    end: u64,
    node: usize,
}

pub struct Symbols {
    ranges: Vec<Range>,
    stubs: HashMap<u64, usize>,
}

impl Symbols {
    pub fn new(
        functions: &[Function],
        plt_names: &HashMap<u64, String>,
        name_to_idx: &HashMap<String, usize>,
    ) -> Self {
        // Two symbols on one address resolve to the last one, the same way the static graph
        // picks the callee for that address.
        let mut by_start: HashMap<u64, Range> = HashMap::new();
        for function in functions {
            let Some(&node) = name_to_idx.get(&function.name) else {
                continue;
            };
            by_start.insert(
                function.address,
                Range {
                    start: function.address,
                    end: function.address + function.size,
                    node,
                },
            );
        }
        let mut ranges: Vec<Range> = by_start.into_values().collect();
        ranges.sort_by_key(|range| range.start);

        let stubs = plt_names
            .iter()
            .filter_map(|(&address, name)| Some((address, *name_to_idx.get(name)?)))
            .collect();

        Symbols { ranges, stubs }
    }

    fn entries(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.ranges
            .iter()
            .map(|range| (range.start, range.node))
            .chain(self.stubs.iter().map(|(&address, &node)| (address, node)))
    }

    fn node_at(&self, address: u64) -> Option<usize> {
        let after = self.ranges.partition_point(|range| range.start <= address);
        let range = &self.ranges[after.checked_sub(1)?];
        (address < range.end).then_some(range.node)
    }
}

#[derive(Default)]
struct Trace {
    node_hits: HashMap<usize, u64>,
    edge_hits: HashMap<(usize, usize), u64>,
}

impl Trace {
    fn call(&mut self, caller: Option<usize>, callee: usize, count: u64) {
        *self.node_hits.entry(callee).or_insert(0) += count;
        if let Some(caller) = caller {
            *self.edge_hits.entry((caller, callee)).or_insert(0) += count;
        }
    }

    fn finish(self, outcome: Outcome, stdout: String, stderr: String) -> TraceResult {
        let mut executed_nodes: Vec<usize> = self.node_hits.keys().copied().collect();
        executed_nodes.sort_unstable();
        let mut executed_edges: Vec<(usize, usize)> = self.edge_hits.keys().copied().collect();
        executed_edges.sort_unstable();
        TraceResult {
            executed_nodes,
            executed_edges,
            node_hits: self.node_hits,
            edge_hits: self.edge_hits,
            exit_code: outcome.exit_code,
            stdout,
            stderr,
            error: outcome.error,
        }
    }
}

struct Outcome {
    exit_code: Option<i32>,
    error: Option<String>,
}

impl Outcome {
    fn failed(message: String) -> Self {
        Outcome {
            exit_code: None,
            error: Some(message),
        }
    }

    fn signaled(signal: Signal) -> Self {
        Outcome::failed(format!("killed by {}", signal.as_str()))
    }
}

// JSON keys must be strings, and "from-to" is how the page already names an edge.
fn edge_keys<S: Serializer>(
    hits: &HashMap<(usize, usize), u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(
        hits.iter()
            .map(|(&(from, to), &count)| (format!("{}-{}", from, to), count)),
    )
}

// Every ptrace request has to come from the thread that spawned the target, so this runs to
// completion on the caller's thread.
pub fn run_ptrace(target: &Target, input: &InputSpec) -> TraceResult {
    let mut trace = Trace::default();
    let (args, input_file) = match prepare_args(target, input) {
        Ok(prepared) => prepared,
        Err(e) => {
            return trace.finish(
                Outcome::failed(format!("can't write input file: {}", e)),
                String::new(),
                String::new(),
            );
        }
    };

    let mut command = Command::new(&target.path);
    command.args(&args);
    unsafe {
        command.pre_exec(|| ptrace::traceme().map_err(io::Error::from));
    }

    let result = match launch(command, input, target.timeout) {
        Ok(launch) => {
            let pid = Pid::from_raw(launch.child.id() as i32);
            let outcome = match session(target, pid, &mut trace) {
                Ok(outcome) => outcome,
                Err(message) => {
                    let _ = signal::killpg(pid, Signal::SIGKILL);
                    Outcome::failed(message)
                }
            };
            let (stdout, stderr, timed_out) = launch.finish();
            trace.finish(
                timed_out_outcome(outcome, timed_out, target),
                stdout,
                stderr,
            )
        }
        Err(e) => trace.finish(
            Outcome::failed(format!("can't run {}: {}", target.path, e)),
            String::new(),
            String::new(),
        ),
    };

    if let Some(path) = input_file {
        let _ = fs::remove_file(path);
    }
    result
}

struct Breakpoint {
    node: usize,
    original: u8,
}

fn session(target: &Target, pid: Pid, trace: &mut Trace) -> Result<Outcome, String> {
    match waitpid(pid, Some(WaitPidFlag::__WALL)) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {}
        Ok(status) => return Err(format!("unexpected state before exec: {:?}", status)),
        Err(e) => return Err(format!("waitpid: {}", e)),
    }
    let bias = load_bias(pid, target.entry_point)?;

    let mut breakpoints: HashMap<u64, Breakpoint> = HashMap::new();
    for (address, node) in target.symbols.entries() {
        let address = address.wrapping_add(bias);
        if breakpoints.contains_key(&address) {
            continue;
        }
        let original = poke_byte(pid, address, 0xcc)
            .map_err(|e| format!("can't set breakpoint at {:#x}: {}", address, e))?;
        breakpoints.insert(address, Breakpoint { node, original });
    }

    let options = Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_EXITKILL;
    ptrace::setoptions(pid, options).map_err(|e| format!("setoptions: {}", e))?;
    ptrace::cont(pid, None).map_err(|e| format!("cont: {}", e))?;

    // Threads and forked children stay in the group, so one wait covers everything the target
    // becomes, and the loop ends once the whole group is reaped.
    let group = Pid::from_raw(-pid.as_raw());
    let mut outcome = None;
    let mut deferred = None;
    loop {
        let status = match deferred.take() {
            Some(status) => status,
            None => match waitpid(group, Some(WaitPidFlag::__WALL)) {
                Ok(status) => status,
                Err(Errno::ECHILD) => break,
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(format!("waitpid: {}", e)),
            },
        };
        match status {
            WaitStatus::Exited(who, code) => {
                if who == pid {
                    outcome = Some(Outcome {
                        exit_code: Some(code),
                        error: None,
                    });
                    let _ = signal::killpg(pid, Signal::SIGKILL);
                }
            }
            WaitStatus::Signaled(who, signal, _) => {
                if who == pid {
                    outcome = Some(Outcome::signaled(signal));
                    let _ = signal::killpg(pid, Signal::SIGKILL);
                }
            }
            WaitStatus::Stopped(who, Signal::SIGTRAP) => {
                match hit(target, &breakpoints, bias, who, trace) {
                    Ok(next) => deferred = next,
                    Err(Errno::ESRCH) => {}
                    Err(e) => return Err(format!("ptrace: {}", e)),
                }
            }
            // A fresh thread or child reports a SIGSTOP that only means it is attached now.
            WaitStatus::Stopped(who, Signal::SIGSTOP) => resume(who, None),
            WaitStatus::Stopped(who, signal) => resume(who, Some(signal)),
            other => {
                if let Some(who) = other.pid() {
                    resume(who, None);
                }
            }
        }
    }

    outcome.ok_or_else(|| "lost track of the process".to_string())
}

// The tracee is a copy of the target at its exec stop, so its auxv already holds AT_ENTRY as
// loaded; the distance to the static entry point is the load bias, zero for a non-PIE image.
fn load_bias(pid: Pid, entry_point: u64) -> Result<u64, String> {
    let auxv =
        fs::read(format!("/proc/{}/auxv", pid)).map_err(|e| format!("can't read auxv: {}", e))?;
    auxv.chunks_exact(16)
        .map(|pair| {
            let key = u64::from_ne_bytes(pair[..8].try_into().expect("8 bytes"));
            let value = u64::from_ne_bytes(pair[8..].try_into().expect("8 bytes"));
            (key, value)
        })
        .find(|&(key, _)| key == AT_ENTRY)
        .map(|(_, entry)| entry.wrapping_sub(entry_point))
        .ok_or_else(|| "no AT_ENTRY in auxv".to_string())
}

// Handles one SIGTRAP; returns a wait status the loop still has to dispatch when the thread
// vanished mid-step instead of stopping again.
fn hit(
    target: &Target,
    breakpoints: &HashMap<u64, Breakpoint>,
    bias: u64,
    who: Pid,
    trace: &mut Trace,
) -> Result<Option<WaitStatus>, Errno> {
    let mut regs = ptrace::getregs(who)?;
    let address = regs.rip.wrapping_sub(1);
    let Some(breakpoint) = breakpoints.get(&address) else {
        resume(who, None);
        return Ok(None);
    };

    let return_address = ptrace::read(who, regs.rsp as AddressType)? as u64;
    // A call at the very end of a function returns to the first byte of the next one, so the
    // byte before the return address is the one that is still inside the caller.
    let caller = target
        .symbols
        .node_at(return_address.wrapping_sub(1).wrapping_sub(bias));
    trace.call(caller, breakpoint.node, 1);

    poke_byte(who, address, breakpoint.original)?;
    regs.rip = address;
    ptrace::setregs(who, regs)?;
    ptrace::step(who, None)?;
    let pending = match waitpid(who, Some(WaitPidFlag::__WALL)) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => None,
        Ok(WaitStatus::Stopped(_, signal)) => Some(signal),
        Ok(status) => return Ok(Some(status)),
        Err(e) => return Err(e),
    };
    poke_byte(who, address, 0xcc)?;
    resume(who, pending);
    Ok(None)
}

fn resume(who: Pid, signal: Option<Signal>) {
    let _ = ptrace::cont(who, signal);
}

// Memory is patched a word at a time, so the byte goes into a fresh copy of what is there now.
fn poke_byte(pid: Pid, address: u64, byte: u8) -> nix::Result<u8> {
    let word = ptrace::read(pid, address as AddressType)?;
    ptrace::write(
        pid,
        address as AddressType,
        (word & !0xff) | c_long::from(byte),
    )?;
    Ok(word as u8)
}

static INPUT_COUNTER: AtomicUsize = AtomicUsize::new(0);

// The upload lands in a temporary file that replaces "@@" among the arguments, the way a
// fuzzer hands over a test case.
fn prepare_args(target: &Target, input: &InputSpec) -> io::Result<(Vec<String>, Option<PathBuf>)> {
    let mut args: Vec<String> = target.args.iter().chain(&input.args).cloned().collect();
    let Some(bytes) = &input.input_file else {
        return Ok((args, None));
    };

    let path = std::env::temp_dir().join(format!(
        "binary2graph-input-{}-{}",
        std::process::id(),
        INPUT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes)?;

    let name = path.to_string_lossy().into_owned();
    let mut placed = false;
    for arg in &mut args {
        if arg == "@@" {
            *arg = name.clone();
            placed = true;
        }
    }
    if !placed {
        args.push(name);
    }
    Ok((args, Some(path)))
}

struct Launch {
    child: Child,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
    watchdog: Watchdog,
}

fn launch(mut command: Command, input: &InputSpec, timeout: Duration) -> io::Result<Launch> {
    let stdin = match input.stdin {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    };
    // Its own process group is what lets the timeout take down the target together with
    // whatever it forked.
    command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;

    if let (Some(mut pipe), Some(text)) = (child.stdin.take(), input.stdin.clone()) {
        // Writing from another thread lets a target that never reads its input run to the end.
        thread::spawn(move || {
            let _ = pipe.write_all(text.as_bytes());
        });
    }
    let stdout = capture(child.stdout.take().expect("stdout is piped"));
    let stderr = capture(child.stderr.take().expect("stderr is piped"));
    let watchdog = Watchdog::arm(Pid::from_raw(child.id() as i32), timeout);

    Ok(Launch {
        child,
        stdout,
        stderr,
        watchdog,
    })
}

impl Launch {
    fn finish(self) -> (String, String, bool) {
        let stdout = self.stdout.join().unwrap_or_default();
        let stderr = self.stderr.join().unwrap_or_default();
        (stdout, stderr, self.watchdog.expired())
    }
}

fn timed_out_outcome(outcome: Outcome, timed_out: bool, target: &Target) -> Outcome {
    if timed_out && outcome.exit_code.is_none() {
        Outcome::failed(format!("timed out after {} s", target.timeout.as_secs()))
    } else {
        outcome
    }
}

fn capture<R: Read + Send + 'static>(mut stream: R) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        // The pipe is drained past the limit, or a chatty target would block on it and run into
        // the timeout.
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let room = OUTPUT_LIMIT - kept.len();
            kept.extend_from_slice(&chunk[..n.min(room)]);
        }
        String::from_utf8_lossy(&kept).into_owned()
    })
}

struct Watchdog {
    _done: mpsc::Sender<()>,
    expired: Arc<AtomicBool>,
}

impl Watchdog {
    fn arm(group: Pid, timeout: Duration) -> Self {
        let (done, rx) = mpsc::channel();
        let expired = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&expired);
        thread::spawn(move || {
            // The sender drops when the run is over, so only a real timeout gets past the wait.
            if rx.recv_timeout(timeout) == Err(RecvTimeoutError::Timeout) {
                flag.store(true, Ordering::SeqCst);
                let _ = signal::killpg(group, Signal::SIGKILL);
            }
        });
        Watchdog {
            _done: done,
            expired,
        }
    }

    fn expired(&self) -> bool {
        self.expired.load(Ordering::SeqCst)
    }
}
