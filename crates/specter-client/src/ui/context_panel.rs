use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{ActivePanel, App, ContextTab, TaskRecordStatus};

fn format_timestamp(ts: &prost_types::Timestamp) -> String {
    chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

pub fn render(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let border_style = if app.active_panel == ActivePanel::ContextPanel {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height < 3 || inner.width < 4 {
        return;
    }

    // Split: tab bar (1 line) + content area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    render_tab_bar(frame, app, chunks[0]);

    match app.context_tab {
        ContextTab::Info => render_info_tab(frame, app, chunks[1]),
        ContextTab::Process => render_process_tab(frame, app, chunks[1]),
        ContextTab::Tasks => render_tasks_tab(frame, app, chunks[1]),
        ContextTab::Network => render_network_tab(frame, app, chunks[1]),
    }
}

fn render_tab_bar(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let focused = app.active_panel == ActivePanel::ContextPanel;
    let mut spans: Vec<Span> = Vec::new();

    for tab in ContextTab::ALL {
        let is_active = tab == app.context_tab;
        let label = format!(" {} ", tab.label());

        let style = if is_active {
            Style::default()
                .fg(if focused { Color::Black } else { Color::White })
                .bg(if focused {
                    Color::Cyan
                } else {
                    Color::DarkGray
                })
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        spans.push(Span::styled(label, style));
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, area);
}

fn render_info_tab(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let label = Style::default().fg(Color::DarkGray);
    let value = Style::default().fg(Color::White);

    let content: Vec<Line> = if let Some(s) = app.selected_session() {
        let first_seen = s
            .first_seen
            .as_ref()
            .map(format_timestamp)
            .unwrap_or_default();
        let last_checkin = s
            .last_checkin
            .as_ref()
            .map(format_timestamp)
            .unwrap_or_default();

        vec![
            Line::from(vec![
                Span::styled("Hostname:  ", label),
                Span::styled(s.hostname.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Username:  ", label),
                Span::styled(s.username.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Domain:    ", label),
                Span::styled("—", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("PID:       ", label),
                Span::styled(s.pid.to_string(), value),
            ]),
            Line::from(vec![
                Span::styled("Process:   ", label),
                Span::styled(s.process_name.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("OS:        ", label),
                Span::styled(s.os_version.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Arch:      ", label),
                Span::styled("x86_64", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("Integrity: ", label),
                Span::styled(s.integrity_level.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Int. IP:   ", label),
                Span::styled(s.internal_ip.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Ext. IP:   ", label),
                Span::styled(s.external_ip.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("Channel:   ", label),
                Span::styled(s.active_channel.clone(), value),
            ]),
            Line::from(vec![
                Span::styled("First:     ", label),
                Span::styled(first_seen, value),
            ]),
            Line::from(vec![
                Span::styled("Checkin:   ", label),
                Span::styled(last_checkin, value),
            ]),
            Line::from(vec![
                Span::styled("ID:        ", label),
                Span::styled(s.id.clone(), value),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No session selected",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let paragraph = Paragraph::new(content).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_process_tab(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let content = if let Some(s) = app.selected_session() {
        // Show the implant process highlighted, with a simple tree stub
        let implant_style = Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD);
        let dim = Style::default().fg(Color::DarkGray);

        vec![
            Line::from(Span::styled(
                "Process Tree",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled("─────────────", dim)),
            Line::from(vec![
                Span::styled("├── ", dim),
                Span::styled("System (PID 4)", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("│   └── ", dim),
                Span::styled("smss.exe (PID 312)", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("├── ", dim),
                Span::styled("explorer.exe (PID 1024)", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("│   └── ", dim),
                Span::styled(format!("{} (PID {})", s.process_name, s.pid), implant_style),
            ]),
            Line::from(Span::raw("")),
            Line::from(Span::styled(
                "Run 'ps' for live process list",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No session selected",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let paragraph = Paragraph::new(content).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_tasks_tab(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let session_id = app.active_session_id.as_deref();

    // Filter tasks for the active session
    let tasks: Vec<_> = app
        .task_records
        .iter()
        .filter(|t| session_id.is_some_and(|sid| t.session_id == sid))
        .collect();

    if tasks.is_empty() {
        let content = vec![Line::from(Span::styled(
            if session_id.is_some() {
                "No tasks for this session"
            } else {
                "No session selected"
            },
            Style::default().fg(Color::DarkGray),
        ))];
        let paragraph = Paragraph::new(content);
        frame.render_widget(paragraph, area);
        return;
    }

    // Header
    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            format!(
                "{:<4} {:<10} {:<3} {:<9} {:<9}",
                "ID", "Type", "St", "Submitted", "Operator"
            ),
            header_style,
        )),
        Line::from(Span::styled("─".repeat(area.width as usize), dim)),
    ];

    let height = area.height as usize;
    let visible_count = height.saturating_sub(2); // minus header lines
    let total = tasks.len();
    let scroll = app.task_scroll.min(total.saturating_sub(visible_count));
    let end = (scroll + visible_count).min(total);

    for task in &tasks[scroll..end] {
        let status_style = match task.status {
            TaskRecordStatus::Pending => Style::default().fg(Color::DarkGray),
            TaskRecordStatus::Running => Style::default().fg(Color::Blue),
            TaskRecordStatus::Complete => Style::default().fg(Color::Green),
            TaskRecordStatus::Failed => Style::default().fg(Color::Red),
        };

        let submitted = task.submitted.format("%H:%M:%S").to_string();

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<4} ", task.id),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("{:<10} ", task.task_type),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(format!("{:<3} ", task.status.icon()), status_style),
            Span::styled(format!("{:<9} ", submitted), dim),
            Span::styled(task.operator.clone(), dim),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

fn render_network_tab(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let content = if let Some(s) = app.selected_session() {
        vec![
            Line::from(Span::styled(
                "Network Connections",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                "───────────────────",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(vec![
                Span::styled("Int. IP: ", Style::default().fg(Color::DarkGray)),
                Span::styled(s.internal_ip.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Ext. IP: ", Style::default().fg(Color::DarkGray)),
                Span::styled(s.external_ip.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Channel: ", Style::default().fg(Color::DarkGray)),
                Span::styled(s.active_channel.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(Span::raw("")),
            Line::from(Span::styled(
                "Detailed connection data coming soon",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No session selected",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let paragraph = Paragraph::new(content).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use crate::app::ContextTab;

    #[test]
    fn test_context_tab_navigation() {
        assert_eq!(ContextTab::Info.next(), ContextTab::Process);
        assert_eq!(ContextTab::Process.next(), ContextTab::Tasks);
        assert_eq!(ContextTab::Tasks.next(), ContextTab::Network);
        assert_eq!(ContextTab::Network.next(), ContextTab::Network); // stays at end

        assert_eq!(ContextTab::Info.prev(), ContextTab::Info); // stays at start
        assert_eq!(ContextTab::Process.prev(), ContextTab::Info);
        assert_eq!(ContextTab::Tasks.prev(), ContextTab::Process);
        assert_eq!(ContextTab::Network.prev(), ContextTab::Tasks);
    }

    #[test]
    fn test_context_tab_labels() {
        assert_eq!(ContextTab::Info.label(), "Info");
        assert_eq!(ContextTab::Process.label(), "Process");
        assert_eq!(ContextTab::Tasks.label(), "Tasks");
        assert_eq!(ContextTab::Network.label(), "Network");
    }

    #[test]
    fn test_context_tab_all() {
        assert_eq!(ContextTab::ALL.len(), 4);
    }
}
