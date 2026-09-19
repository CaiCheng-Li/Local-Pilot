//! Classification of canonical paths into policy classes.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use workstation_core::paths::starts_with_ci;

use crate::protected::{ProtectedMatch, ProtectedRules};

/// Canonical roots that drive classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roots {
    /// Canonical trusted workspace (`<Documents>\Projects`).
    pub trusted: PathBuf,
    /// Canonical `%LOCALAPPDATA%\LocalPilot`.
    pub app_data: PathBuf,
    /// Canonical `%LOCALAPPDATA%\LocalPilot\cache\temp`.
    pub cache_temp: PathBuf,
    /// Canonical directory of the installed application binaries, when it is
    /// outside the trusted workspace (development builds inside a project are
    /// ordinary project files).
    pub install_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "area", rename_all = "snake_case")]
pub enum CacheArea {
    Task { task_id: String },
    Tool { profile: String, scope: String },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum PathClass {
    Trusted,
    CacheTemp(CacheArea),
    ControlData,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub class: PathClass,
    pub protected: Option<ProtectedMatch>,
}

impl Roots {
    pub fn classify_class(&self, path: &Path) -> PathClass {
        if starts_with_ci(path, &self.cache_temp) {
            let rel: Vec<String> = path
                .components()
                .skip(self.cache_temp.components().count())
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let area = match rel.as_slice() {
                [kind, id, ..] if kind.eq_ignore_ascii_case("tasks") => CacheArea::Task {
                    task_id: id.clone(),
                },
                [kind, profile, scope, ..] if kind.eq_ignore_ascii_case("tools") => {
                    CacheArea::Tool {
                        profile: profile.clone(),
                        scope: scope.clone(),
                    }
                }
                _ => CacheArea::Other,
            };
            return PathClass::CacheTemp(area);
        }
        if starts_with_ci(path, &self.app_data) {
            return PathClass::ControlData;
        }
        if let Some(install) = &self.install_dir
            && starts_with_ci(path, install)
        {
            return PathClass::ControlData;
        }
        if starts_with_ci(path, &self.trusted) {
            return PathClass::Trusted;
        }
        PathClass::External
    }

    pub fn classify(
        &self,
        path: &Path,
        protected: &ProtectedRules,
        for_read: bool,
    ) -> Classification {
        Classification {
            class: self.classify_class(path),
            protected: protected.check(path, for_read),
        }
    }

    pub fn is_trusted(&self, path: &Path) -> bool {
        self.classify_class(path) == PathClass::Trusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Roots {
        Roots {
            trusted: PathBuf::from(r"C:\Users\Alice\Documents\Projects"),
            app_data: PathBuf::from(r"C:\Users\Alice\AppData\Local\LocalPilot"),
            cache_temp: PathBuf::from(r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp"),
            install_dir: Some(PathBuf::from(
                r"C:\Users\Alice\AppData\Local\Programs\Local Pilot",
            )),
        }
    }

    #[test]
    fn classes() {
        let r = roots();
        assert_eq!(
            r.classify_class(Path::new(r"C:\Users\Alice\Documents\Projects\Clippy\a.rs")),
            PathClass::Trusted
        );
        assert_eq!(
            r.classify_class(Path::new(r"C:\Users\Alice\Documents\Projects-Backup\a.rs")),
            PathClass::External
        );
        assert_eq!(
            r.classify_class(Path::new(r"C:\Users\Alice\Documents\Projects2")),
            PathClass::External
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\LocalPilot\data\local-pilot.db"
            )),
            PathClass::ControlData
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\LocalPilot\config\settings.json"
            )),
            PathClass::ControlData
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tasks\task_1\x"
            )),
            PathClass::CacheTemp(CacheArea::Task {
                task_id: "task_1".into()
            })
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp\tools\npm\cl_1\x"
            )),
            PathClass::CacheTemp(CacheArea::Tool {
                profile: "npm".into(),
                scope: "cl_1".into()
            })
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\LocalPilot\cache\temp"
            )),
            PathClass::CacheTemp(CacheArea::Other)
        );
        assert_eq!(
            r.classify_class(Path::new(
                r"C:\Users\Alice\AppData\Local\Programs\Local Pilot\local-pilot.exe"
            )),
            PathClass::ControlData
        );
        assert_eq!(
            r.classify_class(Path::new(r"C:\Windows\System32")),
            PathClass::External
        );
    }
}
