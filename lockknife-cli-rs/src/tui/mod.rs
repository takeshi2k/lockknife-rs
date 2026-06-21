use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Terminal;

use crate::app::{AppContext, Result};

pub fn run_tui(ctx: &AppContext) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, ctx);
    restore_terminal(terminal)?;
    result
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, ctx: &AppContext) -> Result<()> {
    loop {
        let devices = ctx.services.adb.list_devices().unwrap_or_default();
        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(8)])
                .split(frame.area());

            let header = Paragraph::new(Text::from(vec![
                Line::styled(
                    "LockKnife Rust-first TUI",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Line::raw(format!("ADB path: {}", ctx.config.adb_path)),
                Line::raw("Disabled: Frida, PDF reports"),
                Line::raw("Press q to exit"),
            ]))
            .block(Block::default().title("Status").borders(Borders::ALL));

            let body = Paragraph::new(Text::from(
                devices
                    .iter()
                    .map(|device| {
                        Line::raw(format!(
                            "{} | {} | {}",
                            device.serial,
                            device.state,
                            device.model.clone().unwrap_or_else(|| "-".to_string())
                        ))
                    })
                    .collect::<Vec<_>>(),
            ))
            .block(Block::default().title("Connected devices").borders(Borders::ALL));

            frame.render_widget(header, layout[0]);
            frame.render_widget(body, layout[1]);
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn restore_terminal(mut terminal: Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
