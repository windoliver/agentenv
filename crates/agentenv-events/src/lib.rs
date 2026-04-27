#![forbid(unsafe_code)]

mod store;

pub use store::{
    default_store_path, EventImportReport, LocalEventStore, StoredEvent, StoredEventKind,
};

#[cfg(test)]
mod tests {
    use super::{default_store_path, LocalEventStore};

    #[test]
    fn local_store_initializes_ops_database() {
        let root = tempfile::tempdir().expect("tempdir");

        let store = LocalEventStore::open(root.path()).expect("open event store");

        assert_eq!(store.path(), default_store_path(root.path()));
        assert!(store
            .list_recent(None, 10)
            .expect("list recent events")
            .is_empty());
    }
}
