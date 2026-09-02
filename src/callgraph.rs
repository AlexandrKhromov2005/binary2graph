use petgraph::dot::{Config, Dot};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum NodeKind {
    Local,  
    Plt,     
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub kind: NodeKind,
}

pub struct CallGraph {
    graph: DiGraph<Node, ()>,
    node_index: HashMap<String, NodeIndex>,
}

impl CallGraph {
    pub fn new() -> Self {
        CallGraph {
            graph: DiGraph::new(),
            node_index: HashMap::new(),
        }
    }

    fn get_or_add(&mut self, name: &str, kind: NodeKind) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(name) {
            idx
        } else {
            let idx = self.graph.add_node(Node {
                name: name.to_string(),
                kind,
            });
            self.node_index.insert(name.to_string(), idx);
            idx
        }
    }

    pub fn add_call(
        &mut self,
        caller: &str,
        caller_kind: NodeKind,
        callee: &str,
        callee_kind: NodeKind,
    ) {
        let caller_idx = self.get_or_add(caller, caller_kind);
        let callee_idx = self.get_or_add(callee, callee_kind);
        self.graph.add_edge(caller_idx, callee_idx, ());
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn to_dot(&self) -> String {
        let dot = Dot::with_attr_getters(
            &self.graph,
            &[Config::EdgeNoLabel, Config::NodeNoLabel],
            &|_g, _e| String::new(),
            &|_g, node_ref| {
                let node = node_ref.1;
                let (fill, shape) = match node.kind {
                    NodeKind::Local => ("#a8d5ff", "ellipse"),
                    NodeKind::Plt => ("#ffcc99", "box"),
                    NodeKind::Unknown => ("#dddddd", "ellipse"),
                };
                format!(
                    "label = \"{}\", style = filled, fillcolor = \"{}\", shape = {}",
                    node.name, fill, shape
                )
            },
        );
        format!("{:?}", dot)
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}