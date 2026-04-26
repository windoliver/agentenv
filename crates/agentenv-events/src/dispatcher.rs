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

    pub fn with_sinks(capacity: usize, sinks: Vec<Box<dyn EventSink>>) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let counters = EventCounters::default();
        spawn_sink_worker(receiver, sinks, counters.clone());
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

    fn increment_dropped_events(&self) {
        self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_sink_errors(&self) {
        self.inner.sink_errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct EventCountersInner {
    dropped_events: AtomicU64,
    sink_errors: AtomicU64,
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

fn spawn_sink_worker(
    mut receiver: mpsc::Receiver<DispatcherMessage>,
    sinks: Vec<Box<dyn EventSink>>,
    counters: EventCounters,
) {
    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            match message {
                DispatcherMessage::Event(event) => {
                    for sink in &sinks {
                        if sink.write_batch(vec![event.clone()]).await.is_err() {
                            counters.increment_sink_errors();
                        }
                    }
                }
                DispatcherMessage::Flush(ack) => {
                    let _ = ack.send(());
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::activity::{ActivityEvent, ActivityKind, ActivityResult};
    use crate::sink::{EventSink, SinkError};

    #[derive(Clone, Default)]
    struct RecordingSink {
        events: Arc<Mutex<Vec<ActivityEvent>>>,
    }

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

    fn event(trace: &str) -> ActivityEvent {
        ActivityEvent::new(
            "2026-04-26T12:00:00Z",
            ActivityKind::SandboxCreate,
            ActivityResult::Ok,
            trace,
        )
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
        let dispatcher = EventDispatcher::for_test(1, Vec::new());

        dispatcher.emitter().emit(event("trace-1"));
        dispatcher.emitter().emit(event("trace-2"));

        assert_eq!(dispatcher.counters().dropped_events(), 1);
    }
}
