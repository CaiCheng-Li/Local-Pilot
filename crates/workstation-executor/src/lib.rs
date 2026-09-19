//! Process execution for Local Pilot: Job Objects, standard-user launches,
//! bounded redacted output capture, and the task manager.

pub mod job;
pub mod manager;
pub mod spawn;

pub use manager::{OutputSlice, TaskEvent, TaskInfo, TaskManager, TaskSpec, TaskStatus};
pub use spawn::{
    Captured, SpawnSpec, cmd_exe, current_process_elevated, resolve_executable, run_captured,
};
