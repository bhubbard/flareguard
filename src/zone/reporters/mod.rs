pub mod html_rep;
pub mod json_rep;
pub mod sarif_rep;
pub mod terminal;

pub use html_rep::render_html;
pub use json_rep::render_json;
pub use sarif_rep::render_sarif;
pub use terminal::render_terminal;
