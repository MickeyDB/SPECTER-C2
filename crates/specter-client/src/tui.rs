use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::app::{App, ConsoleLine, LineKind};
use crate::event_handler::{handle_key_event, EventResult};
use crate::grpc_client::{AppUpdate, SpecterClient};
use crate::ui;

fn init_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn install_panic_handler() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original(info);
    }));
}

/// Run the TUI main loop. Returns when the user quits.
pub async fn run(
    app: &mut App,
    mut update_rx: mpsc::UnboundedReceiver<AppUpdate>,
    client: &SpecterClient,
) -> io::Result<()> {
    install_panic_handler();
    let mut terminal = init_terminal()?;

    loop {
        terminal.draw(|frame| ui::render(frame, app))?;

        // Drain pending updates from background gRPC tasks.
        while let Ok(update) = update_rx.try_recv() {
            match update {
                AppUpdate::Sessions(sessions) => app.update_sessions(sessions),
                AppUpdate::ConnectionStatus(status) => app.connection_status = status,
                AppUpdate::Event(event) => {
                    handle_event_update(app, &event);
                }
            }
        }

        // Poll for keyboard events (100ms tick rate for UI responsiveness).
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match handle_key_event(key, app) {
                        EventResult::Quit => break,
                        EventResult::Continue => {}
                        EventResult::QueueTask {
                            session_id,
                            task_type,
                            args,
                        } => {
                            queue_task_async(client, app, session_id, task_type, args).await;
                        }
                        EventResult::GenerateReport {
                            campaign_id,
                            format,
                        } => {
                            generate_report_async(client, app, campaign_id, format).await;
                        }
                        EventResult::SendChatMessage { content, channel } => {
                            send_chat_async(client, app, content, channel).await;
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

async fn queue_task_async(
    client: &SpecterClient,
    app: &mut App,
    session_id: String,
    task_type: String,
    args: Vec<u8>,
) {
    match client.queue_task(&session_id, &task_type, &args).await {
        Ok(task_id) => {
            let short_id = if task_id.len() > 8 {
                &task_id[..8]
            } else {
                &task_id
            };
            app.console_append(
                ConsoleLine::new(
                    LineKind::System,
                    format!("Task {} dispatched (id: {short_id})", task_type),
                )
                .with_session(session_id),
            );
        }
        Err(e) => {
            app.console_append(
                ConsoleLine::new(LineKind::TaskFailed, format!("Failed to queue task: {e}"))
                    .with_session(session_id),
            );
        }
    }
}

async fn generate_report_async(
    client: &SpecterClient,
    app: &mut App,
    campaign_id: String,
    format: String,
) {
    match client.generate_report(&campaign_id, &format).await {
        Ok(content) => {
            let preview = if content.len() > 500 {
                format!(
                    "{}...\n\n(Report truncated — {} bytes total)",
                    &content[..500],
                    content.len()
                )
            } else {
                content
            };
            app.console_append(ConsoleLine::new(
                LineKind::TaskComplete,
                format!("Report generated successfully:\n{preview}"),
            ));
        }
        Err(e) => {
            app.console_append(ConsoleLine::new(
                LineKind::TaskFailed,
                format!("Failed to generate report: {e}"),
            ));
        }
    }
}

async fn send_chat_async(client: &SpecterClient, app: &mut App, content: String, channel: String) {
    // Add the message locally immediately for responsiveness
    app.chat_messages.push(crate::app::ChatEntry {
        sender: "You".to_string(),
        content: content.clone(),
        timestamp: chrono::Utc::now(),
    });

    if let Err(e) = client.send_chat_message(&content, &channel).await {
        app.console_append(ConsoleLine::new(
            LineKind::Error,
            format!("Failed to send chat message: {e}"),
        ));
    }
}

fn handle_event_update(app: &mut App, event: &specter_common::proto::specter::v1::Event) {
    use specter_common::proto::specter::v1::event::Event as Inner;

    let inner = match &event.event {
        Some(e) => e,
        None => return,
    };

    match inner {
        Inner::TaskEvent(task_event) => {
            if let Some(ref task) = task_event.task {
                let status_str = &task_event.event_type;
                let short_id = if task.id.len() > 8 {
                    &task.id[..8]
                } else {
                    &task.id
                };

                // Show task completion with result in console
                if status_str == "completed" || status_str == "complete" {
                    let result_text = if task.result.is_empty() {
                        "(no output)".to_string()
                    } else {
                        String::from_utf8_lossy(&task.result).to_string()
                    };

                    app.console_append(
                        ConsoleLine::new(
                            LineKind::TaskComplete,
                            format!("Task {short_id} ({}) completed", task.task_type),
                        )
                        .with_session(task.session_id.clone()),
                    );

                    // Append each line of output
                    for line in result_text.lines() {
                        app.console_append(
                            ConsoleLine::new(LineKind::Output, line.to_string())
                                .with_session(task.session_id.clone()),
                        );
                    }
                } else if status_str == "failed" {
                    let err_text = if task.result.is_empty() {
                        "(no details)".to_string()
                    } else {
                        String::from_utf8_lossy(&task.result).to_string()
                    };
                    app.console_append(
                        ConsoleLine::new(
                            LineKind::TaskFailed,
                            format!("Task {short_id} ({}) failed: {err_text}", task.task_type),
                        )
                        .with_session(task.session_id.clone()),
                    );
                }
            }
        }
        Inner::SessionEvent(session_event) => {
            if let Some(ref session) = session_event.session {
                let event_type = &session_event.event_type;
                app.console_append(ConsoleLine::new(
                    LineKind::System,
                    format!(
                        "Session event: {} — {} ({})",
                        event_type, session.hostname, session.username
                    ),
                ));
            }
        }
        Inner::PresenceUpdate(presence_update) => {
            use crate::app::{OperatorPresenceEntry, OperatorPresenceStatus};
            if let Some(ref presence) = presence_update.presence {
                let status = match presence.status {
                    1 => OperatorPresenceStatus::Online,
                    2 => OperatorPresenceStatus::Idle,
                    _ => OperatorPresenceStatus::Offline,
                };

                match presence_update.event_type.as_str() {
                    "disconnected" => {
                        app.operator_presence
                            .retain(|op| op.username != presence.username);
                        app.connected_operators = app.connected_operators.saturating_sub(1);
                    }
                    "connected" => {
                        app.operator_presence
                            .retain(|op| op.username != presence.username);
                        app.operator_presence.push(OperatorPresenceEntry {
                            username: presence.username.clone(),
                            active_session: presence.active_session_id.clone(),
                            status,
                        });
                        app.connected_operators = app.operator_presence.len() as u32;
                    }
                    _ => {
                        // Update existing entry (active_session, idle, etc.)
                        if let Some(op) = app
                            .operator_presence
                            .iter_mut()
                            .find(|op| op.username == presence.username)
                        {
                            op.active_session = presence.active_session_id.clone();
                            op.status = status;
                        }
                    }
                }
            }
        }
        Inner::ChatMessage(chat_msg) => {
            use crate::app::ChatEntry;
            app.chat_messages.push(ChatEntry {
                sender: chat_msg.sender_username.clone(),
                content: chat_msg.content.clone(),
                timestamp: chat_msg
                    .timestamp
                    .as_ref()
                    .map(|ts| {
                        chrono::DateTime::from_timestamp(ts.seconds, 0)
                            .unwrap_or_else(chrono::Utc::now)
                    })
                    .unwrap_or_else(chrono::Utc::now),
            });
            // Keep last 200 messages
            if app.chat_messages.len() > 200 {
                app.chat_messages.drain(..app.chat_messages.len() - 200);
            }
        }
    }
}
