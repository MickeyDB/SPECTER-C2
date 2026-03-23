use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{ActivePanel, App, ConsoleLine, LineKind};

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let border_style = if app.active_panel == ActivePanel::MainPanel {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = if let Some(session) = app.selected_session() {
        format!(" Console — {} ", session.hostname)
    } else {
        " Console ".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height < 2 || inner.width < 4 {
        return;
    }

    // Determine input line height: 1 for normal input, or 1 for reverse search
    let input_height = 1;

    // Split inner area: output area (top) + input line (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(input_height)])
        .split(inner);

    render_output(frame, app, chunks[0]);

    if app.reverse_search.active {
        render_reverse_search(frame, app, chunks[1]);
    } else {
        render_input(frame, app, chunks[1]);
    }

    // Render completion popup above the input line
    if app.completion.visible && !app.completion.items.is_empty() {
        render_completion_popup(frame, app, chunks[0], chunks[1]);
    }
}

fn render_output(frame: &mut Frame, app: &App, area: Rect) {
    let height = area.height as usize;
    let total = app.console_output.len();

    // Calculate visible range based on scroll offset
    let visible_end = if app.console_scroll > 0 {
        total.saturating_sub(app.console_scroll)
    } else {
        total
    };
    let visible_start = visible_end.saturating_sub(height);

    let lines: Vec<Line> = app.console_output[visible_start..visible_end]
        .iter()
        .map(|line| style_console_line(line))
        .collect();

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn style_console_line(line: &ConsoleLine) -> Line<'_> {
    let timestamp = Span::styled(
        format!("[{}] ", line.timestamp.format("%H:%M:%S")),
        Style::default().fg(Color::DarkGray),
    );

    let (content_style, prefix) = match line.kind {
        LineKind::Input => (
            Style::default().fg(Color::White),
            Span::styled("> ", Style::default().fg(Color::Cyan)),
        ),
        LineKind::Output => (
            Style::default().fg(Color::White),
            Span::styled("  ", Style::default()),
        ),
        LineKind::Error => (
            Style::default().fg(Color::Red),
            Span::styled("! ", Style::default().fg(Color::Red)),
        ),
        LineKind::System => (
            Style::default().fg(Color::Yellow),
            Span::styled("* ", Style::default().fg(Color::Yellow)),
        ),
        LineKind::TaskQueued => (
            Style::default().fg(Color::Blue),
            Span::styled("+ ", Style::default().fg(Color::Blue)),
        ),
        LineKind::TaskComplete => (
            Style::default().fg(Color::Green),
            Span::styled("✓ ", Style::default().fg(Color::Green)),
        ),
        LineKind::TaskFailed => (
            Style::default().fg(Color::Red),
            Span::styled("✗ ", Style::default().fg(Color::Red)),
        ),
    };

    let content = Span::styled(&line.content, content_style);

    if let Some(ref session) = line.session_id {
        let session_tag = Span::styled(
            format!("[{}] ", truncate_id(session)),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::DIM),
        );
        Line::from(vec![timestamp, session_tag, prefix, content])
    } else {
        Line::from(vec![timestamp, prefix, content])
    }
}

fn truncate_id(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = Span::styled("specter> ", Style::default().fg(Color::Cyan));
    let input = Span::styled(&app.console_input, Style::default().fg(Color::White));

    let line = Line::from(vec![prompt, input]);
    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, area);

    // Position cursor after the input text
    if app.active_panel == ActivePanel::MainPanel && app.console_focused {
        let prompt_len = "specter> ".len() as u16;
        let cursor_x = area.x + prompt_len + app.console_cursor as u16;
        let cursor_y = area.y;
        frame.set_cursor_position((cursor_x.min(area.x + area.width - 1), cursor_y));
    }
}

fn render_reverse_search(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = Span::styled("(reverse-i-search)`", Style::default().fg(Color::Yellow));
    let query = Span::styled(&app.reverse_search.query, Style::default().fg(Color::White));
    let sep = Span::styled("': ", Style::default().fg(Color::Yellow));
    let matched = Span::styled(
        app.reverse_search.current_match.as_deref().unwrap_or(""),
        Style::default().fg(Color::DarkGray),
    );

    let line = Line::from(vec![prompt, query, sep, matched]);
    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, area);

    // Position cursor within the reverse search query
    if app.active_panel == ActivePanel::MainPanel && app.console_focused {
        let prefix_len = "(reverse-i-search)`".len() as u16;
        let cursor_x = area.x + prefix_len + app.reverse_search.cursor as u16;
        let cursor_y = area.y;
        frame.set_cursor_position((cursor_x.min(area.x + area.width - 1), cursor_y));
    }
}

/// Render the tab-completion popup above the input line.
fn render_completion_popup(frame: &mut Frame, app: &App, output_area: Rect, input_area: Rect) {
    let item_count = app.completion.items.len().min(5);
    let popup_height = item_count as u16;

    if popup_height == 0 || output_area.height < popup_height {
        return;
    }

    // Position popup just above the input line
    let popup_y = input_area.y.saturating_sub(popup_height);
    let popup_width = 30u16.min(input_area.width);
    let prompt_offset = "specter> ".len() as u16;

    let popup_area = Rect {
        x: input_area.x + prompt_offset,
        y: popup_y,
        width: popup_width,
        height: popup_height,
    };

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let lines: Vec<Line> = app
        .completion
        .items
        .iter()
        .take(5)
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.completion.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White).bg(Color::DarkGray)
            };
            Line::from(Span::styled(
                format!(
                    " {:<width$}",
                    item,
                    width = (popup_width as usize).saturating_sub(1)
                ),
                style,
            ))
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, popup_area);
}
