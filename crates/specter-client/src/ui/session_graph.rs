//! ASCII session graph view — shows sessions as nodes with pivot relationships.
//!
//! Toggled with Ctrl-G. Nodes are sessions, edges represent pivot links
//! (SMB/lateral movement parent-child). Uses box-drawing characters and
//! color-codes nodes by session status.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use specter_common::proto::specter::v1::SessionInfo;

use crate::app::App;

/// State for the session graph overlay.
#[derive(Debug, Default)]
pub struct SessionGraphState {
    pub visible: bool,
    pub scroll: usize,
}

impl SessionGraphState {
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
        self.scroll = 0;
    }

    pub fn scroll_up(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_add(n);
    }

    pub fn scroll_down(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_sub(n);
    }
}

/// A pivot relationship between two sessions.
#[derive(Debug, Clone)]
pub struct PivotLink {
    pub parent_id: String,
    pub child_id: String,
    pub link_type: String,
}

/// Render the session graph as a centered overlay.
pub fn render(frame: &mut Frame, app: &App) {
    if !app.session_graph.visible {
        return;
    }

    let area = frame.area();
    if area.width < 20 || area.height < 10 {
        return;
    }

    // 80% width, 80% height centered overlay
    let overlay_width = (area.width as f32 * 0.8) as u16;
    let overlay_height = (area.height as f32 * 0.8) as u16;
    let x = area.x + (area.width - overlay_width) / 2;
    let y = area.y + (area.height - overlay_height) / 2;

    let overlay = Rect {
        x,
        y,
        width: overlay_width,
        height: overlay_height,
    };

    frame.render_widget(Clear, overlay);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Session Graph (Ctrl-G to close) ")
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    if app.sessions.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No active sessions",
            Style::default().fg(Color::DarkGray),
        )));
        frame.render_widget(empty, inner);
        return;
    }

    let lines = build_graph_lines(&app.sessions, &app.pivot_links, inner.width as usize);

    // Apply scroll
    let visible_height = inner.height as usize;
    let total = lines.len();
    let max_scroll = total.saturating_sub(visible_height);
    let scroll = app.session_graph.scroll.min(max_scroll);
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(visible_height);

    let visible_lines: Vec<Line> = lines[start..end].to_vec();
    let paragraph = Paragraph::new(visible_lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

/// Build the ASCII graph lines for rendering.
fn build_graph_lines<'a>(
    sessions: &'a [SessionInfo],
    pivot_links: &[PivotLink],
    _max_width: usize,
) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    // Header
    lines.push(Line::from(vec![
        Span::styled(
            "  Session Topology",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  ({} nodes, {} edges)", sessions.len(), pivot_links.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(""));

    // Find root sessions (not a child of any pivot link)
    let child_ids: Vec<&str> = pivot_links.iter().map(|l| l.child_id.as_str()).collect();
    let roots: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| !child_ids.contains(&s.id.as_str()))
        .collect();

    // Orphan sessions (no parent and no children)
    let parent_ids: Vec<&str> = pivot_links.iter().map(|l| l.parent_id.as_str()).collect();

    if roots.is_empty() {
        // All sessions are standalone
        for session in sessions {
            lines.extend(render_node(session, "", false));
        }
    } else {
        for (i, root) in roots.iter().enumerate() {
            let is_last_root = i == roots.len() - 1;
            lines.extend(render_node(root, "", false));

            // Find children of this root
            let children: Vec<(&SessionInfo, &str)> = pivot_links
                .iter()
                .filter(|l| l.parent_id == root.id)
                .filter_map(|l| {
                    sessions
                        .iter()
                        .find(|s| s.id == l.child_id)
                        .map(|s| (s, l.link_type.as_str()))
                })
                .collect();

            for (j, (child, link_type)) in children.iter().enumerate() {
                let is_last_child = j == children.len() - 1;
                let connector = if is_last_child { "└" } else { "├" };
                let prefix = if is_last_child { "  " } else { "│ " };

                // Edge line
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {connector}── "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(format!("[{link_type}]"), Style::default().fg(Color::Yellow)),
                ]));

                lines.extend(render_node(child, &format!("  {prefix}"), false));

                // Render grandchildren
                let grandchildren: Vec<(&SessionInfo, &str)> = pivot_links
                    .iter()
                    .filter(|l| l.parent_id == child.id)
                    .filter_map(|l| {
                        sessions
                            .iter()
                            .find(|s| s.id == l.child_id)
                            .map(|s| (s, l.link_type.as_str()))
                    })
                    .collect();

                for (k, (grandchild, gc_link)) in grandchildren.iter().enumerate() {
                    let gc_last = k == grandchildren.len() - 1;
                    let gc_connector = if gc_last { "└" } else { "├" };

                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {prefix}  {gc_connector}── "),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(format!("[{gc_link}]"), Style::default().fg(Color::Yellow)),
                    ]));

                    let gc_prefix = if gc_last {
                        format!("  {prefix}    ")
                    } else {
                        format!("  {prefix}  │ ")
                    };
                    lines.extend(render_node(grandchild, &gc_prefix, false));
                }
            }

            if !is_last_root && !parent_ids.contains(&root.id.as_str()) {
                lines.push(Line::from(""));
            }
        }
    }

    // Legend
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Legend: ", Style::default().fg(Color::DarkGray)),
        Span::styled("● ", Style::default().fg(Color::Green)),
        Span::styled("Active  ", Style::default().fg(Color::DarkGray)),
        Span::styled("● ", Style::default().fg(Color::Yellow)),
        Span::styled("Stale  ", Style::default().fg(Color::DarkGray)),
        Span::styled("● ", Style::default().fg(Color::Red)),
        Span::styled("Dead  ", Style::default().fg(Color::DarkGray)),
        Span::styled("● ", Style::default().fg(Color::Cyan)),
        Span::styled("New", Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(vec![Span::styled(
        "  Scroll: PgUp/PgDn | Close: Ctrl-G",
        Style::default().fg(Color::DarkGray),
    )]));

    lines
}

/// Render a single session node as an ASCII box.
fn render_node<'a>(session: &'a SessionInfo, indent: &str, _selected: bool) -> Vec<Line<'a>> {
    let status_color = status_color(session.status);
    let short_id = truncate_id(&session.id);

    let hostname = &session.hostname;
    let user = &session.username;
    let ip = if !session.internal_ip.is_empty() {
        &session.internal_ip
    } else {
        "?.?.?.?"
    };

    // Box width based on content
    let content_line = format!("{hostname} | {user}@{} | {ip}", session.pid);
    let box_width = content_line.len().max(short_id.len() + 4) + 4;

    let top = format!("{indent}┌{}┐", "─".repeat(box_width));
    let bottom = format!("{indent}└{}┘", "─".repeat(box_width));

    vec![
        Line::from(Span::styled(top, Style::default().fg(Color::DarkGray))),
        Line::from(vec![
            Span::styled(format!("{indent}│ "), Style::default().fg(Color::DarkGray)),
            Span::styled("● ", Style::default().fg(status_color)),
            Span::styled(
                format!("{:<width$}", short_id, width = box_width - 4),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("│", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(format!("{indent}│ "), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<width$}", content_line, width = box_width - 2),
                Style::default().fg(Color::White),
            ),
            Span::styled("│", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(Span::styled(bottom, Style::default().fg(Color::DarkGray))),
    ]
}

fn status_color(status: i32) -> Color {
    // SessionStatus enum: 0=Unknown, 1=Active, 2=Stale, 3=Dead, 4=New
    match status {
        1 => Color::Green,
        2 => Color::Yellow,
        3 => Color::Red,
        4 => Color::Cyan,
        _ => Color::DarkGray,
    }
}

fn truncate_id(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_graph_state_toggle() {
        let mut state = SessionGraphState::default();
        assert!(!state.visible);
        state.toggle();
        assert!(state.visible);
        assert_eq!(state.scroll, 0);
        state.toggle();
        assert!(!state.visible);
    }

    #[test]
    fn test_session_graph_state_scroll() {
        let mut state = SessionGraphState::default();
        state.scroll_up(5);
        assert_eq!(state.scroll, 5);
        state.scroll_down(3);
        assert_eq!(state.scroll, 2);
        state.scroll_down(10);
        assert_eq!(state.scroll, 0);
    }

    #[test]
    fn test_status_color() {
        assert_eq!(status_color(1), Color::Green);
        assert_eq!(status_color(2), Color::Yellow);
        assert_eq!(status_color(3), Color::Red);
        assert_eq!(status_color(4), Color::Cyan);
        assert_eq!(status_color(0), Color::DarkGray);
    }

    #[test]
    fn test_truncate_id() {
        assert_eq!(truncate_id("abcdefghij"), "abcdefgh");
        assert_eq!(truncate_id("short"), "short");
    }

    #[test]
    fn test_build_graph_lines_empty() {
        let lines = build_graph_lines(&[], &[], 80);
        // Should have header + legend
        assert!(lines.len() >= 3);
    }

    #[test]
    fn test_build_graph_lines_single_session() {
        let sessions = vec![SessionInfo {
            id: "abc12345".into(),
            hostname: "target-1".into(),
            username: "admin".into(),
            pid: 1234,
            internal_ip: "10.0.0.1".into(),
            status: 1, // Active
            ..Default::default()
        }];
        let lines = build_graph_lines(&sessions, &[], 80);
        // Should contain the session node
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(text.contains("target-1"));
        assert!(text.contains("admin"));
    }

    #[test]
    fn test_build_graph_lines_with_pivot() {
        let sessions = vec![
            SessionInfo {
                id: "parent01".into(),
                hostname: "dc-01".into(),
                username: "SYSTEM".into(),
                pid: 100,
                internal_ip: "10.0.0.1".into(),
                status: 1,
                ..Default::default()
            },
            SessionInfo {
                id: "child001".into(),
                hostname: "ws-01".into(),
                username: "user1".into(),
                pid: 200,
                internal_ip: "10.0.0.2".into(),
                status: 1,
                ..Default::default()
            },
        ];
        let pivots = vec![PivotLink {
            parent_id: "parent01".into(),
            child_id: "child001".into(),
            link_type: "SMB".into(),
        }];
        let lines = build_graph_lines(&sessions, &pivots, 80);
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(text.contains("dc-01"));
        assert!(text.contains("ws-01"));
        assert!(text.contains("[SMB]"));
    }

    #[test]
    fn test_render_node_produces_box() {
        let session = SessionInfo {
            id: "abcdef12".into(),
            hostname: "host-1".into(),
            username: "admin".into(),
            pid: 4444,
            internal_ip: "10.0.0.5".into(),
            status: 1,
            ..Default::default()
        };
        let lines = render_node(&session, "", false);
        assert_eq!(lines.len(), 4); // top, id line, detail line, bottom

        let top_text: String = lines[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(top_text.contains('┌'));
        assert!(top_text.contains('┐'));

        let bottom_text: String = lines[3]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(bottom_text.contains('└'));
        assert!(bottom_text.contains('┘'));
    }

    #[test]
    fn test_pivot_link_struct() {
        let link = PivotLink {
            parent_id: "aaa".into(),
            child_id: "bbb".into(),
            link_type: "SMB".into(),
        };
        assert_eq!(link.parent_id, "aaa");
        assert_eq!(link.child_id, "bbb");
        assert_eq!(link.link_type, "SMB");
    }
}
