use crate::binary::{BinaryInfo, Function};
use crate::callgraph::{GraphExport, NodeKind};
use crate::trace::{Engine, InputSpec, Target};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub binary: String,
    pub info: BinaryInfo,
    pub functions: Vec<Function>,
    pub names: Vec<String>,
    pub kinds: Vec<NodeKind>,
    pub out_adj: Vec<Vec<usize>>,
    pub in_adj: Vec<Vec<usize>>,
    pub name_to_idx: HashMap<String, usize>,
    pub in_degree: Vec<usize>,
    pub out_degree: Vec<usize>,
    pub edge_count: usize,
    pub report_json: String,
    pub meta_json: String,
    pub roots_json: String,
    pub target: Target,
    pub run_lock: Mutex<()>,
}

impl AppState {
    pub fn new(
        binary: String,
        info: BinaryInfo,
        functions: Vec<Function>,
        target: Target,
        export: GraphExport,
        report_json: String,
    ) -> Self {
        let GraphExport { nodes, edges } = export;

        let mut names = Vec::with_capacity(nodes.len());
        let mut kinds = Vec::with_capacity(nodes.len());
        for node in nodes {
            names.push(node.name);
            kinds.push(node.kind);
        }

        let mut out_adj = vec![Vec::new(); names.len()];
        let mut in_adj = vec![Vec::new(); names.len()];
        let mut in_degree = vec![0; names.len()];
        let mut out_degree = vec![0; names.len()];
        for &(from, to) in &edges {
            out_adj[from].push(to);
            in_adj[to].push(from);
            // Degrees stay on the raw edge list, one entry per call site, to match /api/report.
            out_degree[from] += 1;
            in_degree[to] += 1;
        }
        // A function called twice must not widen the neighbourhood or draw a second arrow, and the
        // sorted order is what makes the breadth-first walk reproducible.
        for list in out_adj.iter_mut().chain(in_adj.iter_mut()) {
            list.sort_unstable();
            list.dedup();
        }

        let name_to_idx = names
            .iter()
            .enumerate()
            .map(|(idx, name)| (name.clone(), idx))
            .collect();

        let mut state = AppState {
            binary,
            info,
            functions,
            names,
            kinds,
            out_adj,
            in_adj,
            name_to_idx,
            in_degree,
            out_degree,
            edge_count: edges.len(),
            report_json,
            meta_json: String::new(),
            roots_json: String::new(),
            target,
            run_lock: Mutex::new(()),
        };
        // Neither body depends on the request, so serialising once leaves a string copy per hit.
        state.meta_json = meta_body(&state);
        state.roots_json = roots_body(&state);
        state
    }
}

#[derive(Clone, Copy)]
enum Dir {
    Out,
    In,
    Both,
}

#[derive(Serialize)]
struct MetaNode<'a> {
    name: &'a str,
    kind: &'a NodeKind,
    in_degree: usize,
    out_degree: usize,
}

#[derive(Serialize)]
struct Stats {
    nodes: usize,
    edges: usize,
}

#[derive(Serialize)]
struct Meta<'a> {
    binary: &'a str,
    info: &'a BinaryInfo,
    functions: &'a [Function],
    nodes: Vec<MetaNode<'a>>,
    stats: Stats,
}

#[derive(Serialize)]
struct NeighborNode {
    id: usize,
    has_more: bool,
}

#[derive(Serialize)]
struct Neighborhood {
    nodes: Vec<NeighborNode>,
    edges: Vec<(usize, usize)>,
    truncated: bool,
}

#[derive(Serialize)]
struct Match {
    name: String,
    kind: NodeKind,
    id: Option<usize>,
    address: Option<u64>,
}

#[derive(Serialize)]
struct SearchResult {
    matches: Vec<Match>,
    total: usize,
}

#[derive(Serialize)]
struct Roots {
    entry: Vec<usize>,
    exported: Vec<usize>,
    top: Vec<usize>,
}

#[derive(Deserialize)]
struct NeighborsQuery {
    id: Option<usize>,
    #[serde(default = "default_depth")]
    depth: u32,
    #[serde(default = "default_dir")]
    dir: String,
    #[serde(default = "default_budget")]
    budget: usize,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

#[derive(Deserialize)]
struct RunRequest {
    engine: String,
    stdin: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    input_file: Option<String>,
}

fn default_depth() -> u32 {
    1
}

fn default_dir() -> String {
    "both".to_string()
}

fn default_budget() -> usize {
    200
}

pub async fn serve(state: AppState, port: u16) {
    let shared = Arc::new(state);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/report", get(report))
        .route("/api/meta", get(meta))
        .route("/api/neighbors", get(neighbors))
        .route("/api/search", get(search))
        .route("/api/roots", get(roots))
        .route("/api/run", post(run))
        .with_state(shared);

    let addr = format!("127.0.0.1:{}", port);
    println!("Serving on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("can't bind address");
    axum::serve(listener, app).await.expect("server failed");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn report(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(&state.report_json).expect("stored JSON is valid");
    Json(value)
}

async fn meta(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.meta_json.clone(),
    )
}

async fn roots(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.roots_json.clone(),
    )
}

async fn neighbors(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NeighborsQuery>,
) -> Response {
    let id = match query.id {
        Some(id) if id < state.names.len() => id,
        _ => return (StatusCode::NOT_FOUND, "unknown node").into_response(),
    };
    let Some(dir) = parse_dir(&query.dir) else {
        return (StatusCode::BAD_REQUEST, "unknown dir").into_response();
    };

    let (order, visited, truncated) = walk(&state, id, query.depth, dir, query.budget);

    let nodes = order
        .iter()
        .map(|&node| NeighborNode {
            id: node,
            has_more: has_more(&state, node, &visited),
        })
        .collect();

    let mut sorted = order;
    sorted.sort_unstable();
    let mut edges = Vec::new();
    for &from in &sorted {
        for &to in &state.out_adj[from] {
            if visited[to] {
                edges.push((from, to));
            }
        }
    }

    Json(Neighborhood {
        nodes,
        edges,
        truncated,
    })
    .into_response()
}

async fn search(State(state): State<Arc<AppState>>, Query(query): Query<SearchQuery>) -> Response {
    let needle = query.q.unwrap_or_default().to_lowercase();
    let mut hits: Vec<(usize, Match)> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();

    if !needle.is_empty() {
        for function in &state.functions {
            let Some(at) = function.name.to_lowercase().find(&needle) else {
                continue;
            };
            if !seen.insert(&function.name) {
                continue;
            }
            let id = state.name_to_idx.get(&function.name).copied();
            let kind = id.map_or(NodeKind::Local, |idx| state.kinds[idx].clone());
            hits.push((
                at,
                Match {
                    name: function.name.clone(),
                    kind,
                    id,
                    address: Some(function.address),
                },
            ));
        }

        for (id, name) in state.names.iter().enumerate() {
            let Some(at) = name.to_lowercase().find(&needle) else {
                continue;
            };
            if !seen.insert(name) {
                continue;
            }
            hits.push((
                at,
                Match {
                    name: name.clone(),
                    kind: state.kinds[id].clone(),
                    id: Some(id),
                    address: None,
                },
            ));
        }
    }

    let total = hits.len();
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
    let matches = hits.into_iter().take(50).map(|(_, hit)| hit).collect();

    Json(SearchResult { matches, total }).into_response()
}

async fn run(State(state): State<Arc<AppState>>, Json(request): Json<RunRequest>) -> Response {
    let Some(engine) = Engine::parse(&request.engine) else {
        return (StatusCode::BAD_REQUEST, "unknown engine").into_response();
    };
    let input_file = match request.input_file.map(|text| BASE64_STANDARD.decode(text)) {
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(_)) => {
            return (StatusCode::BAD_REQUEST, "input_file is not base64").into_response();
        }
        None => None,
    };
    let input = InputSpec {
        stdin: request.stdin,
        args: request.args,
        input_file,
    };

    // A run blocks for up to the timeout and ptrace ties it to one thread, so it leaves the
    // async runtime; the lock keeps two requests from tracing two targets at once.
    let result = tokio::task::spawn_blocking(move || {
        let _running = state
            .run_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        engine.run(&state.target, &input)
    })
    .await;

    match result {
        Ok(result) => Json(result).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "run failed").into_response(),
    }
}

fn parse_dir(raw: &str) -> Option<Dir> {
    match raw {
        "out" => Some(Dir::Out),
        "in" => Some(Dir::In),
        "both" => Some(Dir::Both),
        _ => None,
    }
}

fn step_targets(state: &AppState, id: usize, dir: Dir) -> impl Iterator<Item = usize> + '_ {
    let forward: &[usize] = match dir {
        Dir::Out | Dir::Both => &state.out_adj[id],
        Dir::In => &[],
    };
    let backward: &[usize] = match dir {
        Dir::In | Dir::Both => &state.in_adj[id],
        Dir::Out => &[],
    };
    forward.iter().chain(backward).copied()
}

fn walk(
    state: &AppState,
    seed: usize,
    depth: u32,
    dir: Dir,
    budget: usize,
) -> (Vec<usize>, Vec<bool>, bool) {
    let mut visited = vec![false; state.names.len()];
    let mut order = Vec::new();

    // The seed takes a budget slot of its own, so an empty budget leaves nothing to draw.
    if budget == 0 {
        return (order, visited, true);
    }
    visited[seed] = true;
    order.push(seed);

    let mut truncated = false;
    let mut frontier = vec![seed];
    'walk: for _ in 0..depth {
        let mut next = Vec::new();
        for &node in &frontier {
            for target in step_targets(state, node, dir) {
                if visited[target] {
                    continue;
                }
                if order.len() == budget {
                    truncated = true;
                    break 'walk;
                }
                visited[target] = true;
                order.push(target);
                next.push(target);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    (order, visited, truncated)
}

// The marker says the graph continues past this node, which stays true for a neighbour the
// requested direction never followed.
fn has_more(state: &AppState, id: usize, visited: &[bool]) -> bool {
    state.out_adj[id]
        .iter()
        .chain(&state.in_adj[id])
        .any(|&neighbor| !visited[neighbor])
}

fn meta_body(state: &AppState) -> String {
    let nodes = state
        .names
        .iter()
        .enumerate()
        .map(|(id, name)| MetaNode {
            name,
            kind: &state.kinds[id],
            in_degree: state.in_degree[id],
            out_degree: state.out_degree[id],
        })
        .collect();

    let meta = Meta {
        binary: &state.binary,
        info: &state.info,
        functions: &state.functions,
        nodes,
        stats: Stats {
            nodes: state.names.len(),
            edges: state.edge_count,
        },
    };
    serde_json::to_string(&meta).expect("can't serialize meta")
}

fn roots_body(state: &AppState) -> String {
    let entry = state
        .functions
        .iter()
        .find(|f| f.address == state.info.entry_point)
        .and_then(|f| state.name_to_idx.get(&f.name).copied())
        .into_iter()
        .collect();

    let exported = state
        .functions
        .iter()
        .filter(|f| f.exported)
        .filter_map(|f| state.name_to_idx.get(&f.name).copied())
        .collect();

    let mut top: Vec<usize> = (0..state.names.len())
        .filter(|&id| matches!(state.kinds[id], NodeKind::Local) && state.in_degree[id] > 0)
        .collect();
    top.sort_by(|&a, &b| state.in_degree[b].cmp(&state.in_degree[a]).then(a.cmp(&b)));
    top.truncate(10);

    serde_json::to_string(&Roots {
        entry,
        exported,
        top,
    })
    .expect("can't serialize roots")
}
