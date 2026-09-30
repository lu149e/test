//! Secret storage contract. Implemented by the engine (encrypted at rest); providers use it
//! for tokens and sessions without knowing how they are protected.

pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn put(&self, key: &str, value: &str) -> Result<(), String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemorySecretStore(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap().get(key).cloned()
    }
    fn put(&self, key: &str, value: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}
