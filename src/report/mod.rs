pub mod json;
pub mod markdown;
pub mod sarif;
pub mod table;

pub use json::{render_json_report, JsonReport};
pub use markdown::render_markdown_report;
pub use sarif::{generate_sarif_report, SarifReport};
pub use table::{render_terminal_report, ScanFinding};
