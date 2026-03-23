//! Command palette overlay — Ctrl-P fuzzy search across commands, sessions, and recent tasks.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::search::fuzzy::fuzzy_search;

/// Categories for palette items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteCategory {
    Command,
    Session,
    RecentTask,
}

impl std::fmt::Display for PaletteCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command => write!(f, "Command"),
            Self::Session => write!(f, "Session"),
            Self::RecentTask => write!(f, "Recent"),
        }
    }
}

/// A single item in the command palette.
#[derive(Debug, Clone)]
pub struct PaletteItem {
    pub label: String,
    pub description: String,
    pub category: PaletteCategory,
    /// The action string (command name, session ID, etc.)
    pub action: String,
}

/// State for the command palette overlay.
#[derive(Debug, Default)]
pub struct PaletteState {
    pub visible: bool,
    pub query: String,
    pub cursor: usize,
    pub selected: usize,
    pub items: Vec<PaletteItem>,
    pub filtered_indices: Vec<usize>,
}

impl PaletteState {
    pub fn open(&mut self, app_items: Vec<PaletteItem>) {
        self.visible = true;
        self.query.clear();
        self.cursor = 0;
        self.selected = 0;
        self.items = app_items;
        self.update_filter();
    }

    pub fn close(&mut self) {
        self.visible = false;
        self.query.clear();
        self.cursor = 0;
        self.selected = 0;
        self.items.clear();
        self.filtered_indices.clear();
    }

    pub fn insert_char(&mut self, ch: char) {
        self.query.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
        self.update_filter();
        self.selected = 0;
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.query.remove(self.cursor);
            self.update_filter();
            self.selected = 0;
        }
    }

    pub fn delete_char(&mut self) {
        if self.cursor < self.query.len() {
            self.query.remove(self.cursor);
            self.update_filter();
            self.selected = 0;
        }
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.query.len() {
            self.cursor += 1;
        }
    }

    pub fn select_next(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected = (self.selected + 1) % self.filtered_indices.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.filtered_indices.len() - 1);
        }
    }

    /// Get the currently selected palette item, if any.
    pub fn selected_item(&self) -> Option<&PaletteItem> {
        self.filtered_indices
            .get(self.selected)
            .and_then(|&idx| self.items.get(idx))
    }

    fn update_filter(&mut self) {
        if self.query.is_empty() {
            self.filtered_indices = (0..self.items.len()).collect();
            return;
        }

        let search_items: Vec<(usize, &str)> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| (i, item.label.as_str()))
            .collect();

        let results = fuzzy_search(&self.query, &search_items);
        self.filtered_indices = results.into_iter().map(|m| m.index).collect();
    }
}

/// Build the list of palette items from current app state.
pub fn build_palette_items(app: &App) -> Vec<PaletteItem> {
    let mut items = Vec::new();

    // Commands
    for info in app.command_registry.all() {
        items.push(PaletteItem {
            label: info.name.to_string(),
            description: info.description.to_string(),
            category: PaletteCategory::Command,
            action: info.name.to_string(),
        });
    }

    // Sessions
    for session in &app.sessions {
        let short_id = if session.id.len() > 8 {
            &session.id[..8]
        } else {
            &session.id
        };
        items.push(PaletteItem {
            label: format!("{} ({})", session.hostname, short_id),
            description: format!(
                "{}@{} PID:{}",
                session.username, session.hostname, session.pid
            ),
            category: PaletteCategory::Session,
            action: session.id.clone(),
        });
    }

    // Recent tasks (last 50 console inputs)
    let recent: Vec<_> = app.console_history.iter().rev().take(50).cloned().collect();
    for cmd in recent {
        items.push(PaletteItem {
            label: cmd.clone(),
            description: "Recent command".to_string(),
            category: PaletteCategory::RecentTask,
            action: cmd,
        });
    }

    items
}

/// Compute the centered palette overlay area (60% width, 50% height).
fn palette_area(full: Rect) -> Rect {
    let width = (full.width as f32 * 0.6) as u16;
    let height = (full.height as f32 * 0.5) as u16;
    let x = full.x + (full.width.saturating_sub(width)) / 2;
    let y = full.y + (full.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width.max(20), height.max(5))
}

/// Render the command palette overlay.
pub fn render(frame: &mut Frame, app: &App) {
    let palette = &app.palette;
    if !palette.visible {
        return;
    }

    let area = palette_area(frame.area());

    // Clear the area behind the palette
    frame.render_widget(Clear, area);

    // Outer block
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Command Palette (Ctrl-P) ")
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Split inner: search input (1 line) + results list
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    // Search input
    let input_line = Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Cyan)),
        Span::styled(&palette.query, Style::default().fg(Color::White)),
    ]);
    frame.render_widget(Paragraph::new(input_line), chunks[0]);

    // Set cursor position in the search input
    #[allow(clippy::cast_possible_truncation)]
    let cursor_x = chunks[0].x + 2 + palette.cursor as u16;
    let cursor_y = chunks[0].y;
    if cursor_x < chunks[0].x + chunks[0].width {
        frame.set_cursor_position((cursor_x, cursor_y));
    }

    // Results list
    let max_visible = chunks[1].height as usize;
    let items: Vec<ListItem> = palette
        .filtered_indices
        .iter()
        .take(max_visible)
        .enumerate()
        .map(|(display_idx, &item_idx)| {
            let item = &palette.items[item_idx];
            let (cat_color, cat_label) = match item.category {
                PaletteCategory::Command => (Color::Green, "CMD"),
                PaletteCategory::Session => (Color::Yellow, "SES"),
                PaletteCategory::RecentTask => (Color::Blue, "REC"),
            };

            let style = if display_idx == palette.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let cat_style = if display_idx == palette.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(cat_color)
            };

            let desc_style = if display_idx == palette.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("[{cat_label}] "), cat_style),
                Span::styled(&item.label, style),
                Span::styled(format!("  {}", item.description), desc_style),
            ]))
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, chunks[1]);
}
