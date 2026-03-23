use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

/// Render the floating chat panel overlay (toggled via Ctrl-T).
pub fn render(frame: &mut Frame, app: &App) {
    if !app.chat_visible {
        return;
    }

    let area = frame.area();
    // Position: right-bottom floating panel, ~40% width, ~50% height
    let panel_width = (area.width as f32 * 0.4).clamp(30.0, 60.0) as u16;
    let panel_height = (area.height as f32 * 0.5).clamp(10.0, 25.0) as u16;

    let x = area.width.saturating_sub(panel_width).saturating_sub(1);
    let y = area.height.saturating_sub(panel_height).saturating_sub(2); // Above status bar

    let panel_area = Rect::new(x, y, panel_width, panel_height);

    // Clear the background
    frame.render_widget(Clear, panel_area);

    let block = Block::default()
        .title(" Team Chat (Ctrl-T to close) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(panel_area);
    frame.render_widget(block, panel_area);

    // Split inner into messages area and input area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    // Messages
    let mut lines: Vec<Line> = Vec::new();
    for msg in app
        .chat_messages
        .iter()
        .rev()
        .take(chunks[0].height as usize)
    {
        let time = msg.timestamp.format("%H:%M");
        lines.push(Line::from(vec![
            Span::styled(format!("[{time}] "), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}: ", msg.sender),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&msg.content, Style::default().fg(Color::White)),
        ]));
    }
    lines.reverse();

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No messages yet. Type to chat.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let messages_widget = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(messages_widget, chunks[0]);

    // Input line
    let input_line = Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Cyan)),
        Span::styled(&app.chat_input, Style::default().fg(Color::White)),
    ]);
    frame.render_widget(Paragraph::new(input_line), chunks[1]);
}
