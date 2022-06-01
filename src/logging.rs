use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use log::{Log, Metadata, Record};
use once_cell::sync::OnceCell;


/// Logs records in the standard output stream
pub(crate) struct StdoutLogger;

/// Logs records in the provided file by path
pub(crate) struct FileLogger {
    file: Mutex<BufWriter<File>>,
}

/// Forces flushing buffered records to a destination while dropping
pub(crate) struct LogFlushGuard;


pub(crate) const fn make_stdout_logger() -> &'static impl Log {
    const LOGGER: StdoutLogger = StdoutLogger;
    &LOGGER
}

pub(crate) fn make_file_logger(path: &str) -> std::io::Result<&'static impl Log> {
    static LOGGER: OnceCell<FileLogger> = OnceCell::new();
    assert!(LOGGER.get().is_none());

    LOGGER.get_or_try_init(|| {
        FileLogger::new(path)
    })
}


impl Log for StdoutLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} [{:?}] [{}] [{}] {}",
                     chrono::Local::now().format("%T.%6f"),
                     std::thread::current().id(),
                     record.level(),
                     record.target(),
                     record.args(),
            );
        }
    }

    fn flush(&self) {}
}


impl FileLogger {
    pub fn new(path: &str) -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?
            )),
        })
    }
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Err(e) = self.file.lock().unwrap().write_fmt(format_args!(
                "{} [{:?}] [{}] [{}] {}\n",
                chrono::Local::now().format("%T.%6f"),
                std::thread::current().id(),
                record.level(),
                record.target(),
                record.args(),
            )) {
                eprintln!("Log write failure: {}", e);
            }
        }
    }

    fn flush(&self) {
        if let Err(e) = self.file.lock().unwrap().flush() {
            eprintln!("Log flush failure: {}", e);
        }
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        self.flush();
    }
}

impl Drop for LogFlushGuard {
    fn drop(&mut self) {
        log::logger().flush()
    }
}
