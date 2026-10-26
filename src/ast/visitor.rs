use crate::ast::patterns::{check_suspicious_endpoint, shannon_entropy, SuspiciousEndpoint};
use swc_core::common::source_map::SourceMap;
use swc_core::common::sync::Lrc;
use swc_core::common::{Loc, Span};
use swc_core::ecma::ast::*;
use swc_core::ecma::visit::{Visit, VisitWith};

#[derive(Debug, Clone)]
pub struct ApiCallRecord {
    pub api_path: String,
    pub line: usize,
    pub col: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct DynamicCodeRecord {
    pub kind: &'static str,
    pub snippet: String,
    pub line: usize,
    pub col: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct SuspiciousEndpointFinding {
    pub endpoint: SuspiciousEndpoint,
    pub line: usize,
    pub col: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct EntropyFinding {
    pub entropy: f64,
    pub snippet_preview: String,
    pub line: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct PostMessageFinding {
    pub has_wildcard_target: bool,
    pub line: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct TaintSourceFinding {
    pub source_type: &'static str,
    pub api_name: String,
    pub assigned_var: Option<String>,
    pub line: usize,
    pub col: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct TaintSinkFinding {
    pub sink_type: &'static str,
    pub api_name: String,
    pub argument_var: Option<String>,
    pub target_url: Option<String>,
    pub line: usize,
    pub col: usize,
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct VariableAssignment {
    pub target: String,
    pub source_var: String,
    pub line: usize,
    pub file_path: String,
}

pub struct AstScanner<'a> {
    pub file_path: &'a str,
    pub source_map: &'a Lrc<SourceMap>,
    pub api_calls: Vec<ApiCallRecord>,
    pub dynamic_code: Vec<DynamicCodeRecord>,
    pub suspicious_endpoints: Vec<SuspiciousEndpointFinding>,
    pub entropy_findings: Vec<EntropyFinding>,
    pub post_message_calls: Vec<PostMessageFinding>,
    pub side_panel_triggers: Vec<String>,
    pub tab_id_only: bool,
    pub tab_url_or_title_accessed: bool,

    // Taint analysis hooks
    pub taint_sources: Vec<TaintSourceFinding>,
    pub taint_sinks: Vec<TaintSinkFinding>,
    pub assignments: Vec<VariableAssignment>,
}

impl<'a> AstScanner<'a> {
    pub fn new(file_path: &'a str, source_map: &'a Lrc<SourceMap>) -> Self {
        Self {
            file_path,
            source_map,
            api_calls: Vec::new(),
            dynamic_code: Vec::new(),
            suspicious_endpoints: Vec::new(),
            entropy_findings: Vec::new(),
            post_message_calls: Vec::new(),
            side_panel_triggers: Vec::new(),
            tab_id_only: true,
            tab_url_or_title_accessed: false,
            taint_sources: Vec::new(),
            taint_sinks: Vec::new(),
            assignments: Vec::new(),
        }
    }

    fn loc(&self, span: Span) -> Loc {
        self.source_map.lookup_char_pos(span.lo)
    }

    fn check_member_chain(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Member(member) => {
                let obj = self.check_member_chain(&member.obj)?;
                let prop = match &member.prop {
                    MemberProp::Ident(ident) => ident.sym.to_string(),
                    MemberProp::PrivateName(p) => p.name.to_string(),
                    MemberProp::Computed(comp) => {
                        if let Expr::Lit(Lit::Str(s)) = &*comp.expr {
                            s.value.to_string_lossy().to_string()
                        } else {
                            return None;
                        }
                    }
                };
                Some(format!("{}.{}", obj, prop))
            }
            Expr::Ident(ident) => Some(ident.sym.to_string()),
            _ => None,
        }
    }
}

impl<'a> Visit for AstScanner<'a> {
    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        if let Pat::Ident(target_ident) = &n.name {
            let target_name = target_ident.id.sym.to_string();

            if let Some(init) = &n.init {
                if let Expr::Call(call) = &**init {
                    if let Callee::Expr(callee_expr) = &call.callee {
                        if let Some(api) = self.check_member_chain(callee_expr) {
                            if is_sensitive_source(&api) {
                                let loc = self.loc(call.span);
                                self.taint_sources.push(TaintSourceFinding {
                                    source_type: classify_source(&api),
                                    api_name: api.clone(),
                                    assigned_var: Some(target_name.clone()),
                                    line: loc.line,
                                    col: loc.col_display,
                                    file_path: self.file_path.to_string(),
                                });
                            }
                        }
                    }
                } else if let Expr::Member(member) = &**init {
                    if let Some(chain) = self.check_member_chain(&Expr::Member(member.clone())) {
                        if is_sensitive_source(&chain) {
                            let loc = self.loc(member.span);
                            self.taint_sources.push(TaintSourceFinding {
                                source_type: classify_source(&chain),
                                api_name: chain.clone(),
                                assigned_var: Some(target_name.clone()),
                                line: loc.line,
                                col: loc.col_display,
                                file_path: self.file_path.to_string(),
                            });
                        }
                    }
                } else if let Expr::Ident(src_ident) = &**init {
                    let loc = self.loc(n.span);
                    self.assignments.push(VariableAssignment {
                        target: target_name.clone(),
                        source_var: src_ident.sym.to_string(),
                        line: loc.line,
                        file_path: self.file_path.to_string(),
                    });
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        let target_name = match &n.left {
            AssignTarget::Simple(simple) => match simple {
                SimpleAssignTarget::Ident(ident) => Some(ident.id.sym.to_string()),
                SimpleAssignTarget::Member(member) => self.check_member_chain(&Expr::Member(member.clone())),
                _ => None,
            },
            _ => None,
        };

        if let Some(target) = target_name {
            if let Expr::Ident(src) = &*n.right {
                let loc = self.loc(n.span);
                self.assignments.push(VariableAssignment {
                    target,
                    source_var: src.sym.to_string(),
                    line: loc.line,
                    file_path: self.file_path.to_string(),
                });
            } else if let Expr::Call(call) = &*n.right {
                if let Callee::Expr(callee_expr) = &call.callee {
                    if let Some(api) = self.check_member_chain(callee_expr) {
                        if is_sensitive_source(&api) {
                            let loc = self.loc(call.span);
                            self.taint_sources.push(TaintSourceFinding {
                                source_type: classify_source(&api),
                                api_name: api,
                                assigned_var: Some(target),
                                line: loc.line,
                                col: loc.col_display,
                                file_path: self.file_path.to_string(),
                            });
                        }
                    }
                }
            }
        }

        n.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        let loc = self.loc(n.span);

        if let Callee::Expr(callee_expr) = &n.callee {
            if let Expr::Ident(ident) = &**callee_expr {
                let name = ident.sym.as_ref();
                if name == "eval" {
                    self.dynamic_code.push(DynamicCodeRecord {
                        kind: "eval() execution",
                        snippet: "eval(...)".into(),
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                } else if name == "Function" {
                    self.dynamic_code.push(DynamicCodeRecord {
                        kind: "Function() constructor",
                        snippet: "Function(...)".into(),
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                } else if name == "fetch" {
                    let mut arg_var = None;
                    let mut target_url = None;

                    if let Some(first_arg) = n.args.first() {
                        if let Expr::Lit(Lit::Str(s)) = &*first_arg.expr {
                            target_url = Some(s.value.to_string_lossy().to_string());
                        } else if let Expr::Ident(id) = &*first_arg.expr {
                            arg_var = Some(id.sym.to_string());
                        }
                    }

                    if let Some(second_arg) = n.args.get(1) {
                        if let Expr::Object(obj) = &*second_arg.expr {
                            for prop in &obj.props {
                                if let PropOrSpread::Prop(p) = prop {
                                    if let Prop::KeyValue(kv) = &**p {
                                        let key_name = match &kv.key {
                                            PropName::Ident(id) => id.sym.to_string(),
                                            PropName::Str(s) => s.value.to_string_lossy().to_string(),
                                            _ => String::new(),
                                        };
                                        if key_name == "body" {
                                            if let Expr::Ident(body_id) = &*kv.value {
                                                arg_var = Some(body_id.sym.to_string());
                                            } else if let Expr::Call(body_call) = &*kv.value {
                                                if let Callee::Expr(body_callee) = &body_call.callee {
                                                    if let Some(chain) = self.check_member_chain(body_callee) {
                                                        if chain == "JSON.stringify" {
                                                            if let Some(json_arg) = body_call.args.first() {
                                                                if let Expr::Ident(jid) = &*json_arg.expr {
                                                                    arg_var = Some(jid.sym.to_string());
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    self.taint_sinks.push(TaintSinkFinding {
                        sink_type: "fetch",
                        api_name: "fetch".into(),
                        argument_var: arg_var,
                        target_url,
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                }
            }

            if let Some(chain) = self.check_member_chain(callee_expr) {
                if chain.starts_with("chrome.") || chain.starts_with("browser.") {
                    self.api_calls.push(ApiCallRecord {
                        api_path: chain.clone(),
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });

                    if chain.contains("sidePanel.open") || chain.contains("setPanelBehavior") {
                        self.side_panel_triggers.push(chain.clone());
                    }

                    if is_sensitive_source(&chain) {
                        self.taint_sources.push(TaintSourceFinding {
                            source_type: classify_source(&chain),
                            api_name: chain.clone(),
                            assigned_var: None,
                            line: loc.line,
                            col: loc.col_display,
                            file_path: self.file_path.to_string(),
                        });
                    }
                }

                if chain == "setTimeout" || chain == "setInterval" || chain == "window.setTimeout" || chain == "window.setInterval" {
                    if let Some(first_arg) = n.args.first() {
                        if let Expr::Lit(Lit::Str(_)) = &*first_arg.expr {
                            self.dynamic_code.push(DynamicCodeRecord {
                                kind: "setTimeout/setInterval(string) execution",
                                snippet: format!("{}(\"...\")", chain),
                                line: loc.line,
                                col: loc.col_display,
                                file_path: self.file_path.to_string(),
                            });
                        }
                    }
                }

                if chain == "navigator.sendBeacon" {
                    let mut arg_var = None;
                    let mut target_url = None;
                    if let Some(arg0) = n.args.first() {
                        if let Expr::Lit(Lit::Str(s)) = &*arg0.expr {
                            target_url = Some(s.value.to_string_lossy().to_string());
                        }
                    }
                    if let Some(arg1) = n.args.get(1) {
                        if let Expr::Ident(id) = &*arg1.expr {
                            arg_var = Some(id.sym.to_string());
                        }
                    }
                    self.taint_sinks.push(TaintSinkFinding {
                        sink_type: "sendBeacon",
                        api_name: chain.clone(),
                        argument_var: arg_var,
                        target_url,
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                } else if chain.ends_with(".send") || chain == "XMLHttpRequest.prototype.send" {
                    let mut arg_var = None;
                    if let Some(arg0) = n.args.first() {
                        if let Expr::Ident(id) = &*arg0.expr {
                            arg_var = Some(id.sym.to_string());
                        }
                    }
                    self.taint_sinks.push(TaintSinkFinding {
                        sink_type: "XMLHttpRequest / WebSocket",
                        api_name: chain.clone(),
                        argument_var: arg_var,
                        target_url: None,
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                } else if chain == "window.postMessage" || chain.ends_with(".postMessage") {
                    let mut wildcard = false;
                    if let Some(target_origin) = n.args.get(1) {
                        if let Expr::Lit(Lit::Str(s)) = &*target_origin.expr {
                            if s.value.to_string_lossy() == "*" {
                                wildcard = true;
                            }
                        }
                    }
                    self.post_message_calls.push(PostMessageFinding {
                        has_wildcard_target: wildcard,
                        line: loc.line,
                        file_path: self.file_path.to_string(),
                    });
                } else if chain == "document.write" || chain.ends_with(".contentDocument.write") {
                    self.dynamic_code.push(DynamicCodeRecord {
                        kind: "document.write DOM injection",
                        snippet: chain,
                        line: loc.line,
                        col: loc.col_display,
                        file_path: self.file_path.to_string(),
                    });
                }
            }
        }

        n.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, n: &NewExpr) {
        let loc = self.loc(n.span);
        if let Some(callee_name) = self.check_member_chain(&n.callee) {
            if callee_name == "Function" {
                self.dynamic_code.push(DynamicCodeRecord {
                    kind: "new Function() constructor",
                    snippet: "new Function(...)".into(),
                    line: loc.line,
                    col: loc.col_display,
                    file_path: self.file_path.to_string(),
                });
            } else if callee_name == "WebSocket" {
                let mut target_url = None;
                if let Some(args) = &n.args {
                    if let Some(arg0) = args.first() {
                        if let Expr::Lit(Lit::Str(s)) = &*arg0.expr {
                            target_url = Some(s.value.to_string_lossy().to_string());
                        }
                    }
                }
                self.taint_sinks.push(TaintSinkFinding {
                    sink_type: "WebSocket",
                    api_name: "new WebSocket(...)".into(),
                    argument_var: None,
                    target_url,
                    line: loc.line,
                    col: loc.col_display,
                    file_path: self.file_path.to_string(),
                });
            } else if callee_name == "EventSource" {
                self.taint_sinks.push(TaintSinkFinding {
                    sink_type: "EventSource",
                    api_name: "new EventSource(...)".into(),
                    argument_var: None,
                    target_url: None,
                    line: loc.line,
                    col: loc.col_display,
                    file_path: self.file_path.to_string(),
                });
            }
        }
        n.visit_children_with(self);
    }

    fn visit_member_expr(&mut self, n: &MemberExpr) {
        if let MemberProp::Ident(prop_ident) = &n.prop {
            let prop = prop_ident.sym.as_ref();
            if prop == "url" || prop == "title" {
                self.tab_url_or_title_accessed = true;
            }
        }

        if let Some(chain) = self.check_member_chain(&Expr::Member(n.clone())) {
            if chain == "document.cookie" {
                let loc = self.loc(n.span);
                self.taint_sources.push(TaintSourceFinding {
                    source_type: "document.cookie",
                    api_name: chain,
                    assigned_var: None,
                    line: loc.line,
                    col: loc.col_display,
                    file_path: self.file_path.to_string(),
                });
            }
        }

        n.visit_children_with(self);
    }

    fn visit_lit(&mut self, n: &Lit) {
        if let Lit::Str(s) = n {
            let val_cow = s.value.to_string_lossy();
            let val = val_cow.as_ref();

            if let Some(suspicious) = check_suspicious_endpoint(val) {
                let loc = self.loc(s.span);
                self.suspicious_endpoints.push(SuspiciousEndpointFinding {
                    endpoint: suspicious,
                    line: loc.line,
                    col: loc.col_display,
                    file_path: self.file_path.to_string(),
                });
            }

            if val.len() >= 60 {
                let entropy = shannon_entropy(val);
                if entropy >= 5.0 {
                    let loc = self.loc(s.span);
                    self.entropy_findings.push(EntropyFinding {
                        entropy,
                        snippet_preview: val.chars().take(40).collect(),
                        line: loc.line,
                        file_path: self.file_path.to_string(),
                    });
                }
            }
        }
    }
}

fn is_sensitive_source(api: &str) -> bool {
    api.starts_with("chrome.cookies")
        || api.starts_with("chrome.tabs")
        || api.starts_with("chrome.identity")
        || api.starts_with("chrome.history")
        || api.starts_with("chrome.bookmarks")
        || api.starts_with("chrome.storage")
        || api.starts_with("localStorage")
        || api.starts_with("sessionStorage")
        || api == "document.cookie"
        || api.contains("querySelector('input[type=\"password\"]')")
}

fn classify_source(api: &str) -> &'static str {
    if api.starts_with("chrome.cookies") || api == "document.cookie" {
        "Session Cookies & Auth Tokens"
    } else if api.starts_with("chrome.tabs") {
        "Browsing Activity & Tab URLs"
    } else if api.starts_with("chrome.identity") {
        "User Profile & OAuth Tokens"
    } else if api.starts_with("chrome.history") {
        "User Browsing History"
    } else if api.starts_with("chrome.bookmarks") {
        "Saved Bookmarks"
    } else if api.starts_with("chrome.storage") {
        "Extension Local/Sync Storage"
    } else {
        "Sensitive Storage/Data Source"
    }
}
