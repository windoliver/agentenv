#![forbid(unsafe_code)]

pub mod activity;
pub mod audit;
pub mod dispatcher;
pub mod local_ops;
pub mod metrics;
#[cfg(feature = "otel")]
pub mod otel;
pub mod redaction;
pub mod sink;
pub mod store;
pub mod trace;
pub mod webhook;

pub use activity::{ActivityEvent, ActivityKind, ActivityResult, ActorKind};
pub use dispatcher::{EventDispatcher, EventEmitter, NoopEventEmitter, RecordingEventEmitter};
pub use local_ops::{
    default_store_path, EventImportReport, EventStoreError, EventStoreResult, LocalEventStore,
    StoredEvent, StoredEventKind,
};
#[cfg(feature = "otel")]
pub use otel::OtelSink;
pub use sink::{EventSink, SinkConfig, SinkError};
pub use store::SqliteEventStore;
pub use trace::{TraceQuery, TraceRun, TraceToolCall};
pub use webhook::{WebhookConfig, WebhookSink};
