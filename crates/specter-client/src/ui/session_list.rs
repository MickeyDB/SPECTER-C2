use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use specter_common::proto::specter::v1::{SessionInfo, SessionStatus};

use crate::app::{ActivePanel, App};

fn status_color(status: i32) -> Color {
    match SessionStatus::try_from(status) {
        Ok(SessionStatus::Active) => Color::Green,
        Ok(SessionStatus::Stale) => Color::Yellow,
        Ok(SessionStatus::Dead) => Color::Red,
        Ok(SessionStatus::New) => Color::Cyan,
        _ => Color::Gray,
    }
}

fn format_last_checkin(session: &SessionInfo) -> String {
    if let Some(ts) = &session.last_checkin {
        let now = chrono::Utc::now().timestamp();
        let delta = now - ts.seconds;
        if delta < 60 {
            format!("{delta}s")
        } else if delta < 3600 {
            format!("{}m", delta / 60)
        } else {
            format!("{}h", delta / 3600)
        }
    } else {
        "—".to_string()
    }
}

pub fn render(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .map(|s| {
            let color = status_color(s.status);
            let checkin = format_last_checkin(s);

            // Check if any operator is active on this session
            let active_op: Option<&str> = app
                .operator_presence
                .iter()
                .find(|op| op.active_session == s.id)
                .map(|op| op.username.as_str());

            let mut spans = vec![
                Span::styled(format!("{} ", s.hostname), Style::default().fg(color)),
                Span::styled(
                    format!("{}@{} ", s.username, s.pid),
                    Style::default().fg(Color::White),
                ),
                Span::styled(checkin, Style::default().fg(Color::DarkGray)),
            ];

            if let Some(op_name) = active_op {
                spans.push(Span::styled(
                    format!(" [{op_name}]"),
                    Style::default().fg(Color::Magenta),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let border_style = if app.active_panel == ActivePanel::SessionList {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Sessions ")
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::REVERSED),
        );

    let mut state = ListState::default();
    if !app.sessions.is_empty() {
        state.select(Some(app.selected_index));
    }

    frame.render_stateful_widget(list, area, &mut state);
}
