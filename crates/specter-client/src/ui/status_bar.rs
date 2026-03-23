use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, ConnectionStatus};
use crate::input::InputMode;

pub fn render(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (status_text, status_color) = match app.connection_status {
        ConnectionStatus::Connected => ("Connected", Color::Green),
        ConnectionStatus::Disconnected => ("Disconnected", Color::Red),
        ConnectionStatus::Connecting => ("Connecting...", Color::Yellow),
    };

    let (mode_text, mode_color) = match app.input_mode {
        InputMode::Normal => ("NORMAL", Color::Blue),
        InputMode::Command => ("COMMAND", Color::Yellow),
        InputMode::Search => ("SEARCH", Color::Magenta),
        InputMode::Insert => ("INSERT", Color::Green),
    };

    // Time display: UTC or local based on toggle
    let time_str = if app.show_utc_time {
        chrono::Utc::now().format("%H:%M:%S UTC").to_string()
    } else {
        chrono::Local::now().format("%H:%M:%S %Z").to_string()
    };

    let session_count = app.sessions.len();

    let mut spans = vec![
        Span::styled(" SPECTER ", Style::default().fg(Color::Cyan)),
        Span::styled("| ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" {mode_text} "),
            Style::default()
                .fg(Color::Black)
                .bg(mode_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(status_text, Style::default().fg(status_color)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(app.server_addr.clone(), Style::default().fg(Color::White)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{session_count} sessions"),
            Style::default().fg(Color::White),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            if app.operator_presence.is_empty() {
                format!("{} ops", app.connected_operators)
            } else {
                let names: Vec<String> = app
                    .operator_presence
                    .iter()
                    .map(|op| op.display())
                    .collect();
                format!("Operators: {}", names.join(", "))
            },
            Style::default().fg(Color::White),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(time_str, Style::default().fg(Color::White)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("notify:{}", app.notify_level.label()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled("v0.1.0", Style::default().fg(Color::DarkGray)),
    ];

    // Alert ticker — show most recent alert
    if let Some(alert) = app.alert_ticker.latest() {
        let age = chrono::Utc::now()
            .signed_duration_since(alert.timestamp)
            .num_seconds();
        // Only show alerts less than 30 seconds old
        if age < 30 {
            spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(
                format!("⚡ {}", alert.message),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
    }

    // Show command prompt or search query in the status bar when active
    match app.input_mode {
        InputMode::Command => {
            spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(
                format!(":{}", app.command_prompt.input),
                Style::default().fg(Color::Yellow),
            ));
        }
        InputMode::Search => {
            spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(
                format!("/{}", app.search_state.query),
                Style::default().fg(Color::Magenta),
            ));
            if !app.search_state.matches.is_empty() {
                spans.push(Span::styled(
                    format!(
                        " [{}/{}]",
                        app.search_state.match_index + 1,
                        app.search_state.matches.len()
                    ),
                    Style::default().fg(Color::DarkGray),
                ));
            }
        }
        _ => {}
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
