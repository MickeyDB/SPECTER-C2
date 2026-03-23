use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub struct AppLayout {
    pub session_list: Rect,
    pub main_panel: Rect,
    pub context_panel: Rect,
    pub status_bar: Rect,
}

pub fn create_layout(area: Rect) -> AppLayout {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ])
        .split(vertical[0]);

    AppLayout {
        session_list: horizontal[0],
        main_panel: horizontal[1],
        context_panel: horizontal[2],
        status_bar: vertical[1],
    }
}
