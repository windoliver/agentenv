use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use crate::activity::ActivityEvent;
use crate::sink::{EventSink, SinkError};

pub trait EventEmitter: Send + Sync {
    fn emit(&self, event: ActivityEvent);
}

pub struct EventDispatcher {
    sender: mpsc::Sender<DispatcherMessage>,
    counters: EventCounters,
}

impl EventDispatcher {
    pub fn for_test(capacity: usize, sinks: Vec<Box<dyn EventSink>>) -> Self {
        Self::with_sinks(capacity, sinks)
    }

    #[cfg(test)]
    fn for_test_with_hooks(
        capacity: usize,
        sinks: Vec<Box<dyn EventSink>>,
        hooks: DispatchTestHooks,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let counters = EventCounters::default();
        spawn_dispatch_worker_with_hooks(receiver, sinks, capacity.max(1), counters.clone(), hooks);
        Self { sender, counters }
    }

    pub fn with_sinks(capacity: usize, sinks: Vec<Box<dyn EventSink>>) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let counters = EventCounters::default();
        spawn_dispatch_worker(receiver, sinks, capacity.max(1), counters.clone());
        Self { sender, counters }
    }

    pub fn emitter(&self) -> impl EventEmitter + Clone {
        DispatcherEmitter {
            sender: self.sender.clone(),
            counters: self.counters.clone(),
        }
    }

    pub fn counters(&self) -> EventCounters {
        self.counters.clone()
    }

    pub async fn flush(&self) -> Result<(), SinkError> {
        let (ack, flushed) = oneshot::channel();
        self.sender
            .send(DispatcherMessage::Flush(ack))
            .await
            .map_err(|_| SinkError::DispatcherClosed)?;
        flushed.await.map_err(|_| SinkError::DispatcherClosed)
    }
}

#[derive(Clone, Default)]
pub struct EventCounters {
    inner: Arc<EventCountersInner>,
}

impl EventCounters {
    pub fn dropped_events(&self) -> u64 {
        self.inner.dropped_events.load(Ordering::Relaxed)
    }

    pub fn sink_errors(&self) -> u64 {
        self.inner.sink_errors.load(Ordering::Relaxed)
    }

    pub fn sink_snapshots(&self) -> Vec<SinkCounterSnapshot> {
        match self.inner.sink_counters.lock() {
            Ok(sinks) => sinks
                .iter()
                .map(|sink| SinkCounterSnapshot {
                    name: sink.name,
                    dropped_events: sink.dropped_events.load(Ordering::Relaxed),
                    errors: sink.errors.load(Ordering::Relaxed),
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn increment_dropped_events(&self) {
        self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_sink_errors(&self) {
        self.inner.sink_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn add_sink_counters(&self, name: &'static str) -> SinkCounters {
        let counters = SinkCounters {
            name,
            dropped_events: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
        };
        if let Ok(mut sinks) = self.inner.sink_counters.lock() {
            sinks.push(counters.clone());
        }
        counters
    }
}

#[derive(Default)]
struct EventCountersInner {
    dropped_events: AtomicU64,
    sink_errors: AtomicU64,
    sink_counters: Mutex<Vec<SinkCounters>>,
}

#[derive(Clone)]
struct SinkCounters {
    name: &'static str,
    dropped_events: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
}

impl SinkCounters {
    fn increment_dropped_events(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkCounterSnapshot {
    pub name: &'static str,
    pub dropped_events: u64,
    pub errors: u64,
}

#[derive(Clone)]
struct DispatcherEmitter {
    sender: mpsc::Sender<DispatcherMessage>,
    counters: EventCounters,
}

impl EventEmitter for DispatcherEmitter {
    fn emit(&self, event: ActivityEvent) {
        match self.sender.try_send(DispatcherMessage::Event(event)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.increment_dropped_events();
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct NoopEventEmitter;

impl EventEmitter for NoopEventEmitter {
    fn emit(&self, _event: ActivityEvent) {}
}

impl EventEmitter for Arc<dyn EventEmitter> {
    fn emit(&self, event: ActivityEvent) {
        self.as_ref().emit(event);
    }
}

#[derive(Clone, Default)]
pub struct RecordingEventEmitter {
    events: Arc<Mutex<Vec<ActivityEvent>>>,
}

impl RecordingEventEmitter {
    pub fn recorded(&self) -> Vec<ActivityEvent> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => Vec::new(),
        }
    }

    pub fn clear(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }
}

impl EventEmitter for RecordingEventEmitter {
    fn emit(&self, event: ActivityEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

enum DispatcherMessage {
    Event(ActivityEvent),
    Flush(oneshot::Sender<()>),
}

enum SinkMessage {
    Event(ActivityEvent),
    Flush(oneshot::Sender<()>),
}

struct SinkWorker {
    sender: mpsc::Sender<SinkMessage>,
    counters: SinkCounters,
}

#[derive(Clone, Default)]
struct DispatchTestHooks {
    #[cfg(test)]
    sink_event_enqueued: Option<mpsc::UnboundedSender<String>>,
    #[cfg(test)]
    sink_event_dropped: Option<mpsc::UnboundedSender<String>>,
}

fn spawn_dispatch_worker(
    receiver: mpsc::Receiver<DispatcherMessage>,
    sinks: Vec<Box<dyn EventSink>>,
    sink_capacity: usize,
    counters: EventCounters,
) {
    spawn_dispatch_worker_with_hooks(
        receiver,
        sinks,
        sink_capacity,
        counters,
        DispatchTestHooks::default(),
    );
}

fn spawn_dispatch_worker_with_hooks(
    mut receiver: mpsc::Receiver<DispatcherMessage>,
    sinks: Vec<Box<dyn EventSink>>,
    sink_capacity: usize,
    counters: EventCounters,
    hooks: DispatchTestHooks,
) {
    let sink_workers = sinks
        .into_iter()
        .map(|sink| {
            let sink_counters = counters.add_sink_counters(sink.name());
            spawn_sink_worker(sink, sink_capacity, counters.clone(), sink_counters)
        })
        .collect::<Vec<_>>();

    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            match message {
                DispatcherMessage::Event(event) => {
                    for worker in &sink_workers {
                        match worker.sender.try_send(SinkMessage::Event(event.clone())) {
                            Ok(()) => notify_sink_event_enqueued(&hooks, &event),
                            Err(mpsc::error::TrySendError::Full(_))
                            | Err(mpsc::error::TrySendError::Closed(_)) => {
                                notify_sink_event_dropped(&hooks, &event);
                                worker.counters.increment_dropped_events();
                                counters.increment_dropped_events();
                            }
                        }
                    }
                }
                DispatcherMessage::Flush(ack) => {
                    flush_sink_workers(&sink_workers, &counters).await;
                    let _ = ack.send(());
                }
            }
        }
    });
}

#[cfg(test)]
fn notify_sink_event_enqueued(hooks: &DispatchTestHooks, event: &ActivityEvent) {
    if let Some(enqueued) = &hooks.sink_event_enqueued {
        let _ = enqueued.send(event.trace_id.clone());
    }
}

#[cfg(test)]
fn notify_sink_event_dropped(hooks: &DispatchTestHooks, event: &ActivityEvent) {
    if let Some(dropped) = &hooks.sink_event_dropped {
        let _ = dropped.send(event.trace_id.clone());
    }
}

#[cfg(not(test))]
fn notify_sink_event_enqueued(_hooks: &DispatchTestHooks, _event: &ActivityEvent) {}

#[cfg(not(test))]
fn notify_sink_event_dropped(_hooks: &DispatchTestHooks, _event: &ActivityEvent) {}

fn spawn_sink_worker(
    sink: Box<dyn EventSink>,
    capacity: usize,
    counters: EventCounters,
    sink_counters: SinkCounters,
) -> SinkWorker {
    let (sender, mut receiver) = mpsc::channel(capacity);
    let worker_counters = sink_counters.clone();
    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            match message {
                SinkMessage::Event(event) => {
                    if sink.write_batch(vec![event]).await.is_err() {
                        worker_counters.increment_errors();
                        counters.increment_sink_errors();
                    }
                }
                SinkMessage::Flush(ack) => {
                    let _ = ack.send(());
                }
            }
        }
    });
    SinkWorker {
        sender,
        counters: sink_counters,
    }
}

async fn flush_sink_workers(sink_workers: &[SinkWorker], counters: &EventCounters) {
    let mut flushes = Vec::with_capacity(sink_workers.len());
    for worker in sink_workers {
        let sender = worker.sender.clone();
        let sink_counters = worker.counters.clone();
        flushes.push(tokio::spawn(flush_one_sink_worker(sender, sink_counters)));
    }

    for flushed in flushes {
        match flushed.await {
            Ok(Ok(())) => {}
            Ok(Err(sink_counters)) => {
                sink_counters.increment_errors();
                counters.increment_sink_errors();
            }
            Err(_) => counters.increment_sink_errors(),
        }
    }
}

async fn flush_one_sink_worker(
    sender: mpsc::Sender<SinkMessage>,
    counters: SinkCounters,
) -> Result<(), SinkCounters> {
    let (ack, flushed) = oneshot::channel();
    sender
        .send(SinkMessage::Flush(ack))
        .await
        .map_err(|_| counters.clone())?;
    flushed.await.map_err(|_| counters)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use crate::sink::{EventSink, SinkError};
    use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

    #[derive(Clone, Default)]
    struct RecordingSink {
        events: Arc<Mutex<Vec<ActivityEvent>>>,
    }

    struct GatedSink {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: AsyncMutex<Option<oneshot::Receiver<()>>>,
    }

    struct FailingSink;

    #[async_trait::async_trait]
    impl EventSink for RecordingSink {
        fn name(&self) -> &'static str {
            "recording"
        }

        async fn write_batch(&self, events: Vec<ActivityEvent>) -> Result<(), SinkError> {
            self.events.lock().unwrap().extend(events);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl EventSink for GatedSink {
        fn name(&self) -> &'static str {
            "gated"
        }

        async fn write_batch(&self, _events: Vec<ActivityEvent>) -> Result<(), SinkError> {
            if let Some(started) = self.started.lock().unwrap().take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl EventSink for FailingSink {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn write_batch(&self, _events: Vec<ActivityEvent>) -> Result<(), SinkError> {
            Err(SinkError::InvalidSinkUri {
                uri: "test-failure".to_owned(),
            })
        }
    }

    fn event(trace: &str) -> ActivityEvent {
        ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::SandboxCreate,
            ActivityResult::Ok,
            trace,
        )
    }

    async fn wait_for_trace(receiver: &mut mpsc::UnboundedReceiver<String>, trace_id: &str) {
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(received) = receiver.recv().await {
                if received == trace_id {
                    return;
                }
            }
            panic!("event notification channel closed before {trace_id}");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dispatcher_delivers_events_to_sink() {
        let sink = RecordingSink::default();
        let seen = sink.events.clone();
        let dispatcher = EventDispatcher::for_test(16, vec![Box::new(sink)]);

        dispatcher.emitter().emit(event("trace-dispatch"));
        dispatcher.flush().await.unwrap();

        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatcher_counts_drops_when_queue_is_full() {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (enqueued_tx, mut enqueued_rx) = mpsc::unbounded_channel();
        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        let sink = GatedSink {
            started: Mutex::new(Some(started_tx)),
            release: AsyncMutex::new(Some(release_rx)),
        };
        let dispatcher = EventDispatcher::for_test_with_hooks(
            1,
            vec![Box::new(sink)],
            DispatchTestHooks {
                sink_event_enqueued: Some(enqueued_tx),
                sink_event_dropped: Some(dropped_tx),
            },
        );

        dispatcher.emitter().emit(event("trace-1"));
        started_rx.await.unwrap();
        dispatcher.emitter().emit(event("trace-2"));
        wait_for_trace(&mut enqueued_rx, "trace-2").await;
        dispatcher.emitter().emit(event("trace-3"));
        wait_for_trace(&mut dropped_rx, "trace-3").await;

        assert_eq!(dispatcher.counters().dropped_events(), 1);
        let snapshots = dispatcher.counters().sink_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].dropped_events, 1);
        release_tx.send(()).unwrap();
        dispatcher.flush().await.unwrap();
    }

    #[tokio::test]
    async fn slow_sink_does_not_block_fast_sink() {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let slow = GatedSink {
            started: Mutex::new(Some(started_tx)),
            release: AsyncMutex::new(Some(release_rx)),
        };
        let fast = RecordingSink::default();
        let seen = fast.events.clone();
        let dispatcher = EventDispatcher::for_test(16, vec![Box::new(slow), Box::new(fast)]);

        dispatcher.emitter().emit(event("trace-independent"));
        started_rx.await.unwrap();

        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            loop {
                if !seen.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        release_tx.send(()).unwrap();
        dispatcher.flush().await.unwrap();
    }

    #[tokio::test]
    async fn sink_errors_are_counted() {
        let dispatcher = EventDispatcher::for_test(16, vec![Box::new(FailingSink)]);

        dispatcher.emitter().emit(event("trace-failing"));
        dispatcher.flush().await.unwrap();

        assert_eq!(dispatcher.counters().sink_errors(), 1);
        let snapshots = dispatcher.counters().sink_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].errors, 1);
    }
}
