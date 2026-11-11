use std::sync::{Mutex, TryLockError};

pub const FAULTED: &str = "faulted; restart the BEAM before retrying";

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    Busy,
    Faulted,
}

// Never clear poison implicitly: upstream unwind safety is not established.
// A poison is terminal for this library instance and is distinct from load.
pub struct Admission(Mutex<()>);

impl Admission {
    pub const fn new() -> Self {
        Self(Mutex::new(()))
    }

    pub fn status(&self) -> Status {
        match self.0.try_lock() {
            Ok(_) => Status::Idle,
            Err(TryLockError::WouldBlock) => Status::Busy,
            Err(TryLockError::Poisoned(_)) => Status::Faulted,
        }
    }

    pub fn run<T>(&self, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _guard = match self.0.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err("busy".into()),
            Err(TryLockError::Poisoned(_)) => return Err(FAULTED.into()),
        };
        work()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn busy_does_not_execute_decode_or_work() {
        let gate = Admission::new();
        let calls = Cell::new(0);
        let result = gate.run(|| {
            assert_eq!(gate.status(), Status::Busy);
            gate.run(|| {
                calls.set(calls.get() + 1);
                Ok(())
            })
        });
        assert_eq!(result, Err("busy".into()));
        assert_eq!(calls.get(), 0);
        assert_eq!(gate.status(), Status::Idle);
    }

    #[test]
    fn ordinary_error_releases_admission() {
        let gate = Admission::new();
        assert_eq!(
            gate.run::<()>(|| Err("invalid input".into())),
            Err("invalid input".into())
        );
        assert_eq!(gate.status(), Status::Idle);
        assert_eq!(gate.run(|| Ok(42)), Ok(42));
    }

    #[test]
    fn unwind_is_terminal_fault_and_never_retries_work() {
        let gate = Admission::new();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            gate.run::<()>(|| panic!("test-only injected panic"))
        }));
        assert!(panic.is_err());
        assert_eq!(gate.status(), Status::Faulted);
        let calls = Cell::new(0);
        for _ in 0..3 {
            assert_eq!(
                gate.run(|| {
                    calls.set(calls.get() + 1);
                    Ok(())
                }),
                Err(FAULTED.into())
            );
        }
        assert_eq!(calls.get(), 0);
    }
}
