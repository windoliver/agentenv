use ratatui::{prelude::*, widgets::*};

use crate::{
    app::App,
    model::{Pane, ViewMode},
    theme::Theme,
};

pub fn render_app(frame: &mut Frame<'_>, app: &App, theme: Theme) {
    let area = frame.area();
    if area.height < 10 || area.width < 40 {
        frame.render_widget(
            Paragraph::new("agentenv\nterminal too small").style(theme.active_border()),
            area,
        );
        return;
    }

    let root = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(2),
    ])
    .split(area);

    render_header(frame, root[0], app, theme);
    render_body(frame, root[1], app, theme);
    render_footer(frame, root[2], app);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let snapshot = app.snapshot();
    let header = format!(
        " agentenv | {} envs | {} events/min ",
        snapshot.envs.len(),
        snapshot.events_per_minute
    );
    frame.render_widget(Paragraph::new(header).style(theme.header()), area);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let upper =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[0]);
    let lower =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);

    render_envs(frame, upper[0], app, theme);
    render_events(frame, upper[1], app, theme);
    render_approvals(frame, lower[0], app, theme);
    render_detail(frame, lower[1], app, theme);
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let footer = if app.mode() == ViewMode::Command || !app.command_buffer().is_empty() {
        format!(":{}", app.command_buffer())
    } else {
        "[Tab] pane  [a-z] env  [A] approvals  [L] logs  [P] policy  [?] help  [q] quit".to_owned()
    };
    let status = app.status().unwrap_or("");
    frame.render_widget(Paragraph::new(format!("{footer}\n{status}")), area);
}

fn render_envs(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .envs
        .iter()
        .enumerate()
        .map(|(index, env)| {
            let jump = jump_label(index);
            let marker = if index == app.selected_env_index() {
                ">"
            } else {
                " "
            };
            let line = Line::from(format!(
                "{marker} {jump} {:<16} {:<8} {:<10} {:<10} {}",
                env.name, env.agent, env.sandbox, env.context, env.status
            ));
            if index == app.selected_env_index() {
                line.style(theme.selected())
            } else {
                line
            }
        })
        .collect::<Vec<_>>();
    let rows = rows_or_empty(rows, "No envs");
    let block = pane_block("Envs", app.active_pane() == Pane::Envs, theme);
    frame.render_widget(Paragraph::new(rows).block(block), area);
}

fn render_events(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .events
        .iter()
        .map(|event| {
            let reason = event.reason.as_deref().unwrap_or("");
            Line::from(format!(
                "{} [{}] {} {} {}",
                event.ts, event.env, event.kind, event.subject, reason
            ))
        })
        .collect::<Vec<_>>();
    let rows = rows_or_empty(rows, "No events");
    let block = pane_block("Events", app.active_pane() == Pane::Events, theme);
    frame.render_widget(Paragraph::new(rows).block(block), area);
}

fn render_approvals(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let rows = app
        .snapshot()
        .approvals
        .iter()
        .enumerate()
        .map(|(index, approval)| {
            let marker = if index == app.selected_approval_index() {
                ">"
            } else {
                " "
            };
            let line = Line::from(format!(
                "{marker} {} [{}] {} {}",
                approval.request_id, approval.env, approval.subject, approval.reason
            ));
            if index == app.selected_approval_index() {
                line.style(theme.selected())
            } else {
                line
            }
        })
        .collect::<Vec<_>>();
    let rows = rows_or_empty(rows, "No approvals");
    let block = pane_block("Approvals", app.active_pane() == Pane::Approvals, theme);
    frame.render_widget(Paragraph::new(rows).block(block), area);
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let lines = app
        .snapshot()
        .detail
        .as_ref()
        .map(|detail| {
            detail
                .lines
                .iter()
                .map(|line| Line::from(line.clone()))
                .collect()
        })
        .unwrap_or_else(|| vec![Line::from("No env selected")]);
    let block = pane_block("Detail", app.active_pane() == Pane::Detail, theme);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn pane_block(title: &'static str, active: bool, theme: Theme) -> Block<'static> {
    let title = if active {
        format!("* {title}")
    } else {
        title.to_owned()
    };
    let style = if active {
        theme.active_border()
    } else {
        theme.inactive_border()
    };
    Block::bordered().title(title).border_style(style)
}

fn rows_or_empty<'a>(mut rows: Vec<Line<'a>>, empty: &'static str) -> Vec<Line<'a>> {
    if rows.is_empty() {
        rows.push(Line::from(empty));
    }
    rows
}

fn jump_label(index: usize) -> String {
    if index < 26 {
        format!("[{}]", (b'a' + index as u8) as char)
    } else {
        "[ ]".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::render_app;
    use crate::{
        app::App,
        model::{ApprovalRow, DetailState, EnvRow, EventRow, OpsSnapshot},
        theme::Theme,
    };
    use ratatui::{backend::TestBackend, Terminal};

    fn text_from_terminal(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    fn sample_app() -> App {
        App::new(OpsSnapshot {
            envs: vec![EnvRow {
                name: "alpha".to_owned(),
                agent: "codex".to_owned(),
                sandbox: "openshell".to_owned(),
                context: "filesystem".to_owned(),
                status: "running".to_owned(),
            }],
            events: vec![EventRow {
                ts: "12:00:00".to_owned(),
                env: "alpha".to_owned(),
                kind: "egress_denied".to_owned(),
                subject: "metadata".to_owned(),
                reason: Some("denied_cloud_metadata".to_owned()),
            }],
            approvals: vec![ApprovalRow {
                request_id: "req_1".to_owned(),
                env: "alpha".to_owned(),
                agent: Some("codex".to_owned()),
                subject: "api.stripe.com:443".to_owned(),
                reason: "egress".to_owned(),
            }],
            detail: Some(DetailState {
                env: "alpha".to_owned(),
                lines: vec!["policy: balanced".to_owned()],
            }),
            events_per_minute: 12,
        })
    }

    fn env_row(name: impl Into<String>) -> EnvRow {
        EnvRow {
            name: name.into(),
            agent: "codex".to_owned(),
            sandbox: "openshell".to_owned(),
            context: "filesystem".to_owned(),
            status: "running".to_owned(),
        }
    }

    #[test]
    fn renders_all_four_panes() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::color()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        for expected in [
            "agentenv",
            "Envs",
            "Events",
            "Approvals",
            "Detail",
            "alpha",
            "req_1",
            "policy: balanced",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected} in {rendered}"
            );
        }
    }

    #[test]
    fn monochrome_render_uses_textual_selection_marker() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::mono()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        assert!(rendered.contains("> [a] alpha"), "rendered was {rendered}");
    }

    #[test]
    fn jump_labels_do_not_repeat_after_z() {
        let backend = TestBackend::new(120, 80);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = App::new(OpsSnapshot {
            envs: (0..27)
                .map(|index| env_row(format!("env-{index:02}")))
                .collect(),
            ..OpsSnapshot::empty()
        });

        terminal
            .draw(|frame| render_app(frame, &app, Theme::mono()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        assert_eq!(
            rendered.matches("[a]").count(),
            1,
            "rendered was {rendered}"
        );
        assert!(
            rendered.contains("  [ ] env-26"),
            "27th env should not advertise [a]: {rendered}"
        );
    }

    #[test]
    fn small_terminal_renders_clear_fallback() {
        let backend = TestBackend::new(39, 9);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::mono()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        assert!(rendered.contains("agentenv"), "rendered was {rendered}");
        assert!(
            rendered.contains("terminal too small"),
            "rendered was {rendered}"
        );
    }

    #[test]
    fn monochrome_render_marks_active_pane_in_text() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let app = sample_app();

        terminal
            .draw(|frame| render_app(frame, &app, Theme::mono()))
            .expect("draw");

        let rendered = text_from_terminal(&terminal);
        assert!(rendered.contains("* Envs"), "rendered was {rendered}");
    }
}
