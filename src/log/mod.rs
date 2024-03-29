#![allow(unused_macros)]
use self::simple_logger::SimpleLogger;
use self::syslog::Syslog;
pub use log::Level;
use std::ops::Deref;

mod simple_logger;
mod syslog;

// TODO: logger_macro has an allow_unused that should be removed
macro_rules! logger_macro {
    ($name:ident is $rule_level:ident to $target:expr, $d:tt) => {
        macro_rules! $name {
            ($d($d arg:tt)+) => (::log::log!(target: $target, $crate::log::Level::$rule_level, $d($d arg)+));
        }

        #[allow(unused)]
        pub(crate) use $name;
    };
    ($name:ident is $rule_level:ident to $target:expr) => {
        logger_macro!($name is $rule_level to $target, $);
    };
}

logger_macro!(auth_error is Error to "sudo::auth");
logger_macro!(auth_warn is Warn to "sudo::auth");
logger_macro!(auth_info is Info to "sudo::auth");
logger_macro!(auth_debug is Debug to "sudo::auth");
logger_macro!(auth_trace is Trace to "sudo::auth");

logger_macro!(user_error is Error to "sudo::user");
logger_macro!(user_warn is Warn to "sudo::user");
logger_macro!(user_info is Info to "sudo::user");
logger_macro!(user_debug is Debug to "sudo::user");
logger_macro!(user_trace is Trace to "sudo::user");

// TODO: dev_logger_macro has an allow_unused that should be removed
macro_rules! dev_logger_macro {
    ($name:ident is $rule_level:ident to $target:expr, $d:tt) => {
        macro_rules! $name {
            ($d($d arg:tt)+) => {
                if std::cfg!(feature = "dev") {
                    (::log::log!(
                        target: $target,
                        $crate::log::Level::$rule_level,
                        "{}: {}",
                        std::panic::Location::caller(),
                        format_args!($d($d arg)+)
                    ));
                }
            };
        }

        #[allow(unused)]
        pub(crate) use $name;
    };
    ($name:ident is $rule_level:ident to $target:expr) => {
        dev_logger_macro!($name is $rule_level to $target, $);
    };
}

dev_logger_macro!(dev_error is Error to "sudo::dev");
dev_logger_macro!(dev_warn is Warn to "sudo::dev");
dev_logger_macro!(dev_info is Info to "sudo::dev");
dev_logger_macro!(dev_debug is Debug to "sudo::dev");
dev_logger_macro!(dev_trace is Trace to "sudo::dev");

#[derive(Default)]
pub struct SudoLogger(Vec<(String, Box<dyn log::Log>)>);

impl SudoLogger {
    pub fn new(prefix: &'static str) -> Self {
        let mut logger: Self = Default::default();

        logger.add_logger("sudo::auth", Syslog);

        logger.add_logger("sudo::user", SimpleLogger::to_stderr(prefix));

        #[cfg(feature = "dev")]
        {
            let path = option_env!("SUDO_DEV_LOGS")
                .map(|s| s.into())
                .unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("sudo-dev-{}.log", std::process::id()))
                });
            logger.add_logger("sudo::dev", SimpleLogger::to_file(path, "").unwrap());
        }

        logger
    }

    pub fn into_global_logger(self) {
        log::set_boxed_logger(Box::new(self))
            .map(|()| log::set_max_level(log::LevelFilter::Trace))
            .expect("Could not set previously set logger");
    }

    /// Add a logger for a specific prefix to the stack
    fn add_logger(
        &mut self,
        prefix: impl ToString + Deref<Target = str>,
        logger: impl log::Log + 'static,
    ) {
        self.add_boxed_logger(prefix, Box::new(logger))
    }

    /// Add a boxed logger for a specific prefix to the stack
    fn add_boxed_logger(
        &mut self,
        prefix: impl ToString + Deref<Target = str>,
        logger: Box<dyn log::Log>,
    ) {
        let prefix = if prefix.ends_with("::") {
            prefix.to_string()
        } else {
            // given a prefix `my::prefix`, we want to match `my::prefix::somewhere`
            // but not `my::prefix_to_somewhere`
            format!("{}::", prefix.to_string())
        };
        self.0.push((prefix, logger))
    }
}

impl log::Log for SudoLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.0.iter().any(|(_, l)| l.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        for (prefix, l) in self.0.iter() {
            if record.target() == &prefix[..prefix.len() - 2] || record.target().starts_with(prefix)
            {
                l.log(record);
            }
        }
    }

    fn flush(&self) {
        for (_, l) in self.0.iter() {
            l.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SudoLogger;

    #[test]
    fn can_construct_logger() {
        let logger = SudoLogger::new("sudo: ");
        let len = if cfg!(feature = "dev") { 3 } else { 2 };
        assert_eq!(logger.0.len(), len);
    }
}
