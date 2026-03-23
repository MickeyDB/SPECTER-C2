mod chat_panel;
pub mod console;
mod context_panel;
mod layout;
mod main_panel;
pub mod output_format;
pub mod palette;
pub mod session_graph;
mod session_list;
mod status_bar;

use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App) {
    let areas = layout::create_layout(frame.area());
    session_list::render(frame, app, areas.session_list);
    main_panel::render(frame, app, areas.main_panel);
    context_panel::render(frame, app, areas.context_panel);
    status_bar::render(frame, app, areas.status_bar);

    // Overlays (rendered last, on top)
    palette::render(frame, app);
    session_graph::render(frame, app);
    chat_panel::render(frame, app);
}
