use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register, Command},
    logger::Logger,
    settings,
};
use bstr::BStr;
use log::{info, LevelFilter};
use serde_json::json;

struct YARAScanner;

impl Command for YARAScanner {
    fn action(&self, view: &BinaryView) {
        let mut buf = Vec::new();

        view.read_into_vec(&mut buf, view.start(), view.len());

        info!("Read in");

        let mut compiler = yara_x::Compiler::new();

        compiler
            .add_source(
                r#"
                rule SysLibraryFrameworks_present {
                    strings:
                        $ = "/System/Library/Frameworks/"
                    condition:
                        all of them
                }
            "#,
            )
            .unwrap();

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
            info!("Matched on {}", mr.identifier());
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
        "YARA-X Scanning",
        "Tag YARA rule hits in bndb via the YARA-X engine.",
        YARAScanner {},
    );

    let settings = settings::Settings::new("default");
    settings.register_group("yara-x-binja", "yara-x-binja");

    let default_path = format!(".{}rules", std::path::MAIN_SEPARATOR);
    info!("Looking for YARA rules in {} by default", default_path);

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

    info!("yara-x-binja initialized successfully");

    true
}
