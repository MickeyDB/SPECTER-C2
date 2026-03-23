use ratatui::layout::Alignment;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{ActivePanel, App};

const BANNER: &str = r"
  ____  ____  _____ ____ _____ _____ ____
 / ___||  _ \| ____/ ___|_   _| ____|  _ \
 \___ \| |_) |  _|| |     | | |  _| | |_) |
  ___) |  __/| |__| |___  | | | |___|  _ <
 |____/|_|   |_____\____| |_| |_____|_| \_\

         Command & Control Framework
";

pub fn render(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // When console is focused or we have an active session, render the console
    if app.console_focused || app.active_session_id.is_some() {
        super::console::render(frame, app, area);
        return;
    }

    // Default: show the SPECTER banner
    let border_style = if app.active_panel == ActivePanel::MainPanel {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let lines: Vec<Line> = BANNER
        .lines()
        .map(|l| {
            Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(Color::Cyan),
            ))
        })
        .collect();

    let paragraph = Paragraph::new(lines).alignment(Alignment::Center).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" SPECTER C2 ")
            .border_style(border_style),
    );

    frame.render_widget(paragraph, area);
}
