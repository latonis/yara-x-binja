use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register, Command},
    interaction::{FormInputBuilder, FormResponses},
    logger::Logger,
    settings,
};
use bstr::BStr;
use log::{error, info, LevelFilter};
use serde_json::json;

struct YARAScanner;

struct RuleLoader;

impl Command for YARAScanner {
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

        let results = scanner.scan(&buf).unwrap();

        let tt = view.create_tag_type("YARA-X Matches", "🟪");

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

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

impl Command for RuleLoader {
    fn action(&self, view: &BinaryView) {
        let responses = FormInputBuilder::new()
            .multiline_field("YARA Rules", None)
            .get_form_input("Add YARA Rules");

        if let FormResponses::String(r) = &responses[0] {
            info!("{:?}", r);
            settings::Settings::new("default").set_string(
                "yara-x-binja.rules",
                r,
                Some(view),
                None,
            );
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn UIPluginInit() -> bool {
    Logger::new("yara-x-binja")
        .with_level(LevelFilter::Info)
        .init();

    register(
        "YARA-X\\Scan",
        "Tag YARA rule hits in bndb via the YARA-X engine.",
        YARAScanner {},
    );

    register(
        "YARA-X\\Add YARA Rules",
        "Load YARA rules as a string into the YARA-X engine.",
        RuleLoader {},
    );

    let settings = settings::Settings::new("default");
    settings.register_group("yara-x-binja", "yara-x-binja");

    let default_path = format!(".{}rules", std::path::MAIN_SEPARATOR);

    let properties = json!(
        {
            "title": "Directory for YARA rules",
            "type": "string",
            "default": default_path,
            "description": "The directory where YARA rules can be found for scanning the current binary",
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
        }
    );

    settings.register_setting_json("yara-x-binja.rule_directory", properties.to_string());

    let properties = json!(
        {
            "title": "YARA Rules",
            "type": "string",
            "default": "",
            "description": "YARA Rules as strings to be used for scanning the current binary",
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
        }
    );

    settings.register_setting_json("yara-x-binja.rules", properties.to_string());

    info!("yara-x-binja initialized successfully");

    true
}
