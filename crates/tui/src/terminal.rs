use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event as CrosstermEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::{sync::mpsc, time};

use crate::{
    app::{App, AppIntent},
    backend::OpsBackend,
    model::CommandAction,
    render::render_app,
    theme::Theme,
};

#[derive(Debug, Clone)]
pub struct TermOptions {
    pub no_color: bool,
    pub refresh_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentOutcome {
    pub quit: bool,
    pub refresh: bool,
}

impl IntentOutcome {
    const NONE: Self = Self {
        quit: false,
        refresh: false,
    };
    const QUIT: Self = Self {
        quit: true,
        refresh: false,
    };
    const REFRESH: Self = Self {
        quit: false,
        refresh: true,
    };
}

pub async fn execute_intent<B>(backend: &mut B, intent: AppIntent) -> Result<IntentOutcome>
where
    B: OpsBackend,
{
    match intent {
        AppIntent::None => Ok(IntentOutcome::NONE),
        AppIntent::Refresh => Ok(IntentOutcome::REFRESH),
        AppIntent::Quit => Ok(IntentOutcome::QUIT),
        AppIntent::Execute(CommandAction::DestroyEnv(env)) => {
            backend.destroy_env(&env).await?;
            Ok(IntentOutcome::REFRESH)
        }
        AppIntent::AllowApproval(request_id) => {
            backend.allow_approval(&request_id).await?;
            Ok(IntentOutcome::REFRESH)
        }
        AppIntent::DenyApproval(request_id) => {
            backend.deny_approval(&request_id).await?;
            Ok(IntentOutcome::REFRESH)
        }
    }
}

pub async fn run_terminal<B>(mut backend: B, options: TermOptions) -> Result<()>
where
    B: OpsBackend,
{
    let initial = backend.load_snapshot(None).await?;
    let mut app = App::new(initial);
    let theme = if options.no_color || std::env::var_os("NO_COLOR").is_some() {
        Theme::mono()
    } else {
        Theme::color()
    };

    enable_raw_mode().context("enable terminal raw mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen).context("enter alternate screen") {
        let _ = disable_raw_mode();
        return Err(error);
    }

    let backend_terminal = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend_terminal).context("create terminal") {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(error);
        }
    };

    let result = run_loop(
        &mut terminal,
        &mut app,
        &mut backend,
        theme,
        options.refresh_interval,
    )
    .await;
    let cleanup_result = cleanup_terminal(&mut terminal);

    match (result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_loop<B>(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    backend: &mut B,
    theme: Theme,
    refresh_interval: Duration,
) -> Result<()>
where
    B: OpsBackend,
{
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _input_reader = InputReader::spawn(tx);

    let mut interval = time::interval(nonzero_interval(refresh_interval));
    loop {
        if app.take_dirty() {
            terminal
                .draw(|frame| render_app(frame, app, theme))
                .context("draw term ui")?;
        }

        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };

                if let CrosstermEvent::Key(key) = event {
                    let intent = app.handle_key(key);
                    match execute_intent(backend, intent).await {
                        Ok(outcome) if outcome.quit => break,
                        Ok(outcome) if outcome.refresh => refresh_snapshot(app, backend).await,
                        Ok(_) => {}
                        Err(error) => app.set_status(error.to_string()),
                    }
                }
            }
            _ = interval.tick() => refresh_snapshot(app, backend).await,
        }
    }

    Ok(())
}

struct InputReader {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl InputReader {
    fn spawn(tx: mpsc::UnboundedSender<CrosstermEvent>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match event::poll(Duration::from_millis(50)) {
                    Ok(true) => match event::read() {
                        Ok(event) => {
                            if tx.send(event).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });

        Self {
            stop,
            join: Some(join),
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn refresh_snapshot<B>(app: &mut App, backend: &mut B)
where
    B: OpsBackend,
{
    let selected_env = app.selected_env_name().map(str::to_owned);
    match backend.load_snapshot(selected_env.as_deref()).await {
        Ok(snapshot) => app.apply_snapshot(snapshot),
        Err(error) => app.set_status(error.to_string()),
    }
}

fn cleanup_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    let raw_result = disable_raw_mode().context("disable terminal raw mode");
    let screen_result =
        execute!(terminal.backend_mut(), LeaveAlternateScreen).context("leave alternate screen");
    let cursor_result = terminal.show_cursor().context("show cursor");

    raw_result?;
    screen_result?;
    cursor_result?;
    Ok(())
}

fn nonzero_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        Duration::from_millis(250)
    } else {
        interval
    }
}

#[cfg(test)]
mod tests {
    use super::{execute_intent, nonzero_interval, IntentOutcome};
    use crate::{
        app::AppIntent,
        backend::OpsBackend,
        model::{CommandAction, OpsSnapshot},
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingBackend {
        loaded: usize,
        destroyed: Vec<String>,
        allowed: Vec<String>,
        denied: Vec<String>,
    }

    #[async_trait(?Send)]
    impl OpsBackend for RecordingBackend {
        async fn load_snapshot(&mut self, _selected_env: Option<&str>) -> Result<OpsSnapshot> {
            self.loaded += 1;
            Ok(OpsSnapshot::empty())
        }

        async fn destroy_env(&mut self, env: &str) -> Result<()> {
            self.destroyed.push(env.to_owned());
            Ok(())
        }

        async fn allow_approval(&mut self, request_id: &str) -> Result<()> {
            self.allowed.push(request_id.to_owned());
            Ok(())
        }

        async fn deny_approval(&mut self, request_id: &str) -> Result<()> {
            self.denied.push(request_id.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn execute_intent_calls_backend() {
        let mut backend = RecordingBackend::default();

        let destroy = execute_intent(
            &mut backend,
            AppIntent::Execute(CommandAction::DestroyEnv("demo".to_owned())),
        )
        .await
        .expect("destroy intent");
        let allow = execute_intent(&mut backend, AppIntent::AllowApproval("req_1".to_owned()))
            .await
            .expect("allow intent");
        let deny = execute_intent(&mut backend, AppIntent::DenyApproval("req_2".to_owned()))
            .await
            .expect("deny intent");

        assert_eq!(destroy, IntentOutcome::REFRESH);
        assert_eq!(allow, IntentOutcome::REFRESH);
        assert_eq!(deny, IntentOutcome::REFRESH);
        assert_eq!(backend.loaded, 0);
        assert_eq!(backend.destroyed, ["demo"]);
        assert_eq!(backend.allowed, ["req_1"]);
        assert_eq!(backend.denied, ["req_2"]);
    }

    #[tokio::test]
    async fn execute_intent_reports_quit_without_backend_call() {
        let mut backend = RecordingBackend::default();

        assert_eq!(
            execute_intent(&mut backend, AppIntent::Quit)
                .await
                .expect("quit intent"),
            IntentOutcome::QUIT
        );
        assert_eq!(
            execute_intent(&mut backend, AppIntent::None)
                .await
                .expect("none intent"),
            IntentOutcome::NONE
        );

        assert_eq!(backend.loaded, 0);
        assert!(backend.destroyed.is_empty());
        assert!(backend.allowed.is_empty());
        assert!(backend.denied.is_empty());
    }

    #[tokio::test]
    async fn execute_intent_refresh_indicates_refresh_without_backend_call() {
        let mut backend = RecordingBackend::default();

        assert_eq!(
            execute_intent(&mut backend, AppIntent::Refresh)
                .await
                .expect("refresh intent"),
            IntentOutcome::REFRESH
        );

        assert_eq!(backend.loaded, 0);
        assert!(backend.destroyed.is_empty());
        assert!(backend.allowed.is_empty());
        assert!(backend.denied.is_empty());
    }

    #[test]
    fn nonzero_interval_replaces_zero_with_fallback() {
        assert_eq!(nonzero_interval(Duration::ZERO), Duration::from_millis(250));
        assert_eq!(
            nonzero_interval(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
    }
}
