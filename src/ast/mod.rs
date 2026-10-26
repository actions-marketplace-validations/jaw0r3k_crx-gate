pub mod patterns;
pub mod visitor;

use crate::archive::ExtensionPackage;
pub use patterns::{check_html_csp_violations, check_suspicious_endpoint, shannon_entropy, HtmlViolation, SuspiciousEndpoint};
use rayon::prelude::*;
use swc_core::common::source_map::SourceMap;
use swc_core::common::sync::Lrc;
use swc_core::common::FileName;
use swc_core::ecma::parser::{lexer::Lexer, EsSyntax, Parser, StringInput, Syntax};
use swc_core::ecma::visit::VisitWith;
pub use visitor::{
    ApiCallRecord, AstScanner, DynamicCodeRecord, EntropyFinding, PostMessageFinding,
    SuspiciousEndpointFinding, TaintSinkFinding, TaintSourceFinding, VariableAssignment,
};

#[derive(Debug, Clone)]
pub struct AstFileReport {
    pub file_path: String,
    pub api_calls: Vec<ApiCallRecord>,
    pub dynamic_code: Vec<DynamicCodeRecord>,
    pub suspicious_endpoints: Vec<SuspiciousEndpointFinding>,
    pub entropy_findings: Vec<EntropyFinding>,
    pub post_message_calls: Vec<PostMessageFinding>,
    pub side_panel_triggers: Vec<String>,
    pub tab_id_only: bool,
    pub tab_url_or_title_accessed: bool,
    pub taint_sources: Vec<TaintSourceFinding>,
    pub taint_sinks: Vec<TaintSinkFinding>,
    pub assignments: Vec<VariableAssignment>,
    pub parse_errors: Vec<String>,
}

pub fn analyze_js_content(file_path: &str, content: &str) -> AstFileReport {
    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(
        FileName::Custom(file_path.to_string()).into(),
        content.to_string(),
    );

    let lexer = Lexer::new(
        Syntax::Es(EsSyntax {
            jsx: true,
            fn_bind: true,
            decorators: true,
            decorators_before_export: true,
            export_default_from: true,
            import_attributes: true,
            auto_accessors: true,
            explicit_resource_management: true,
            ..Default::default()
        }),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );

    let mut parser = Parser::new_from(lexer);
    let mut parse_errors = Vec::new();

    match parser.parse_program() {
        Ok(program) => {
            let mut scanner = AstScanner::new(file_path, &cm);
            program.visit_with(&mut scanner);

            AstFileReport {
                file_path: file_path.to_string(),
                api_calls: scanner.api_calls,
                dynamic_code: scanner.dynamic_code,
                suspicious_endpoints: scanner.suspicious_endpoints,
                entropy_findings: scanner.entropy_findings,
                post_message_calls: scanner.post_message_calls,
                side_panel_triggers: scanner.side_panel_triggers,
                tab_id_only: scanner.tab_id_only,
                tab_url_or_title_accessed: scanner.tab_url_or_title_accessed,
                taint_sources: scanner.taint_sources,
                taint_sinks: scanner.taint_sinks,
                assignments: scanner.assignments,
                parse_errors,
            }
        }
        Err(err) => {
            parse_errors.push(format!("{:?}", err));
            AstFileReport {
                file_path: file_path.to_string(),
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
                parse_errors,
            }
        }
    }
}

pub fn analyze_package_scripts(package: &ExtensionPackage) -> Vec<AstFileReport> {
    let js_files = package.js_files();

    js_files
        .par_iter()
        .map(|(path, content)| analyze_js_content(path, content))
        .collect()
}
