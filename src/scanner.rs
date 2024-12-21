use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::Command,
    settings,
};
use bstr::BStr;
use log::{error, info};

pub struct Scanner;

impl Command for Scanner {
    fn action(&self, view: &BinaryView) {
        let mut buf = Vec::new();

        view.read_into_vec(&mut buf, view.start(), view.len());

        let mut compiler = yara_x::Compiler::new();

        let raw_rules =
            settings::Settings::new("default").get_string("yara-x-binja.rules", Some(view), None);

        if compiler.add_source(raw_rules.as_bytes()).is_err() {
            error!("Error loading rule content from {:?}", raw_rules);
        }

        let mut dir_entry = settings::Settings::new("default")
            .get_string("yara-x-binja.rule_directory", Some(view), None)
            .to_string();

        if dir_entry.contains('~') {
            if let Some(home_dir) = dirs::home_dir() {
                if let Some(home_dir) = home_dir.to_str() {
                    dir_entry = dir_entry.replace("~", home_dir);
                }
            }
        }

        if !dir_entry.as_str().ends_with(std::path::MAIN_SEPARATOR) {
            dir_entry.push(std::path::MAIN_SEPARATOR);
        }

        if let Ok(path) = std::fs::canonicalize(std::path::Path::new(&dir_entry)) {
            if path.is_dir() {
                if let Ok(entries) = path.read_dir() {
                    entries.for_each(|f| {
                        if let Ok(file_path) = f {
                            if let Ok(file_content) = std::fs::read_to_string(file_path.path()) {
                                if compiler.add_source(file_content.as_bytes()).is_err() {
                                    error!("Error loading rule content from {:?}", file_path);
                                }
                            }
                        }
                    });
                } else {
                    info!("Failed to read rules from path {}", dir_entry.as_str());
                }
            } else {
                info!("Path given ({:?}) is not a directory!", path.as_os_str());
            }
        } else {
            info!("path could not be opened ({})", dir_entry);
            info!(
                "{:?}",
                std::fs::canonicalize(std::path::Path::new(&dir_entry))
            )
        }

        let rules = compiler.build();

        let mut scanner = yara_x::Scanner::new(&rules);

        let results = scanner.scan(&buf);

        if let Ok(results) = results {
            let tt = view
                .get_tag_type("YARA-X Matches")
                .unwrap_or(view.create_tag_type("YARA-X Matches", "🟪"));

            for mr in results.matching_rules() {
                for p in mr.patterns() {
                    for m in p.matches() {
                        view.add_tag(
                            view.start() + m.range().start as u64,
                            &tt,
                            format!("Matched YARA rule ({})", mr.identifier()),
                            false,
                        );

                        info!(
                            "Data Matched {:?} at offset {}",
                            BStr::new(m.data()),
                            m.range().start
                        );
                    }
                }

                // matches like these occur with module usage, no pattern exists. tag start of file
                if mr.patterns().len() == 0 {
                    view.add_tag(
                        view.start(),
                        &tt,
                        format!("Matched YARA rule ({})", mr.identifier()),
                        false,
                    );
                }
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
