use crate::ast::AstFileReport;
use crate::taint::sinks::NetworkSinkKind;
use crate::taint::sources::SensitiveSourceKind;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLeakPath {
    pub source_kind: SensitiveSourceKind,
    pub source_api: String,
    pub source_location: String,
    pub sink_kind: NetworkSinkKind,
    pub sink_api: String,
    pub sink_location: String,
    pub sink_target_url: Option<String>,
    pub flow_trace: Vec<String>,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

pub struct TaintGraphEngine {
    adjacency: HashMap<String, Vec<GraphNode>>,
    sources: Vec<GraphSource>,
    sinks: Vec<GraphSink>,
}

#[derive(Debug, Clone)]
enum GraphNode {
    Variable(String),
    SinkIndex(usize),
}

#[derive(Debug, Clone)]
struct GraphSource {
    kind: SensitiveSourceKind,
    api: String,
    assigned_var: Option<String>,
    file: String,
    line: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GraphSink {
    kind: NetworkSinkKind,
    api: String,
    argument_var: Option<String>,
    target_url: Option<String>,
    file: String,
    line: usize,
}

impl TaintGraphEngine {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
        }
    }

    pub fn populate_from_reports(&mut self, reports: &[AstFileReport]) {
        for report in reports {
            for src in &report.taint_sources {
                let kind = if src.api_name.contains("cookies") {
                    SensitiveSourceKind::Cookies
                } else if src.api_name.contains("tabs") {
                    SensitiveSourceKind::TabBrowsingHistory
                } else if src.api_name.contains("identity") {
                    SensitiveSourceKind::AuthIdentityTokens
                } else if src.api_name.contains("history") {
                    SensitiveSourceKind::TabBrowsingHistory
                } else if src.api_name.contains("storage") {
                    SensitiveSourceKind::StorageSecrets
                } else {
                    SensitiveSourceKind::Cookies
                };

                self.sources.push(GraphSource {
                    kind,
                    api: src.api_name.clone(),
                    assigned_var: src.assigned_var.clone(),
                    file: src.file_path.clone(),
                    line: src.line,
                });
            }

            for assign in &report.assignments {
                self.adjacency
                    .entry(assign.source_var.clone())
                    .or_default()
                    .push(GraphNode::Variable(assign.target.clone()));
            }

            for sink in &report.taint_sinks {
                let kind = if sink.sink_type == "fetch" {
                    NetworkSinkKind::Fetch
                } else if sink.sink_type == "sendBeacon" {
                    NetworkSinkKind::SendBeacon
                } else if sink.sink_type == "WebSocket" {
                    NetworkSinkKind::WebSocket
                } else if sink.sink_type == "EventSource" {
                    NetworkSinkKind::EventSource
                } else {
                    NetworkSinkKind::XmlHttpRequest
                };

                let sink_idx = self.sinks.len();
                self.sinks.push(GraphSink {
                    kind,
                    api: sink.api_name.clone(),
                    argument_var: sink.argument_var.clone(),
                    target_url: sink.target_url.clone(),
                    file: sink.file_path.clone(),
                    line: sink.line,
                });

                if let Some(arg) = &sink.argument_var {
                    self.adjacency
                        .entry(arg.clone())
                        .or_default()
                        .push(GraphNode::SinkIndex(sink_idx));
                }
            }
        }
    }

    pub fn find_leak_paths(&self) -> Vec<TaintLeakPath> {
        let mut leak_paths = Vec::new();
        let mut visited_paths = HashSet::new();

        for src in &self.sources {
            let src_loc = format!("{}:{}", src.file, src.line);

            if let Some(initial_var) = &src.assigned_var {
                let mut queue = VecDeque::new();
                queue.push_back((initial_var.clone(), vec![format!("{}: initial assignment to '{}'", src.api, initial_var)]));

                let mut visited_vars = HashSet::new();
                visited_vars.insert(initial_var.clone());

                while let Some((curr_var, path_history)) = queue.pop_front() {
                    if let Some(edges) = self.adjacency.get(&curr_var) {
                        for edge in edges {
                            match edge {
                                GraphNode::Variable(next_var) => {
                                    if !visited_vars.contains(next_var) {
                                        visited_vars.insert(next_var.clone());
                                        let mut new_history = path_history.clone();
                                        new_history.push(format!("propagated to '{}'", next_var));
                                        queue.push_back((next_var.clone(), new_history));
                                    }
                                }
                                GraphNode::SinkIndex(sink_idx) => {
                                    let sink = &self.sinks[*sink_idx];
                                    let sink_loc = format!("{}:{}", sink.file, sink.line);
                                    let path_key = format!("{}->{}", src_loc, sink_loc);

                                    if !visited_paths.contains(&path_key) {
                                        visited_paths.insert(path_key);

                                        let mut final_trace = vec![format!("Source: {} ({})", src.api, src_loc)];
                                        final_trace.extend(path_history.clone());
                                        final_trace.push(format!("Sink: {} ({})", sink.api, sink_loc));

                                        leak_paths.push(TaintLeakPath {
                                            source_kind: src.kind.clone(),
                                            source_api: src.api.clone(),
                                            source_location: src_loc.clone(),
                                            sink_kind: sink.kind.clone(),
                                            sink_api: sink.api.clone(),
                                            sink_location: sink_loc,
                                            sink_target_url: sink.target_url.clone(),
                                            flow_trace: final_trace,
                                            severity: "critical".into(),
                                            title: "Confirmed Sensitive Data Exfiltration Path".into(),
                                            description: format!(
                                                "Static taint engine traced data flow from sensitive source '{}' ({}) into external network sink '{}'.",
                                                src.api, src_loc, sink.api
                                            ),
                                            remediation: "Ensure sensitive credentials and user browsing data never flow directly into unverified external network endpoints.".into(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                for sink in &self.sinks {
                    if sink.file == src.file && sink.line >= src.line && (sink.line - src.line) <= 5 {
                        let sink_loc = format!("{}:{}", sink.file, sink.line);
                        let path_key = format!("{}->{}", src_loc, sink_loc);

                        if !visited_paths.contains(&path_key) {
                            visited_paths.insert(path_key);
                            leak_paths.push(TaintLeakPath {
                                source_kind: src.kind.clone(),
                                source_api: src.api.clone(),
                                source_location: src_loc.clone(),
                                sink_kind: sink.kind.clone(),
                                sink_api: sink.api.clone(),
                                sink_location: sink_loc,
                                sink_target_url: sink.target_url.clone(),
                                flow_trace: vec![
                                    format!("Source: {} ({})", src.api, src_loc),
                                    format!("Immediate call to sink: {} ({}:{})", sink.api, sink.file, sink.line),
                                ],
                                severity: "critical".into(),
                                title: "Direct Sensitive Data Ingestion into Network Sink".into(),
                                description: format!(
                                    "Sensitive source '{}' is invoked immediately adjacent to network sink '{}'.",
                                    src.api, sink.api
                                ),
                                remediation: "Do not pass sensitive browser state into outbound network requests.".into(),
                            });
                        }
                    }
                }
            }
        }

        leak_paths
    }
}
