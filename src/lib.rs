use binaryninja::{command::register, logger::Logger, settings};
use log::{info, LevelFilter};
use serde_json::json;

mod loader;
mod scanner;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn UIPluginInit() -> bool {
    Logger::new("yara-x-binja")
        .with_level(LevelFilter::Info)
        .init();

    register(
        "YARA-X\\Scan",
        "Tag YARA rule hits in bndb via the YARA-X engine.",
        scanner::Scanner {},
    );

    register(
        "YARA-X\\Add YARA Rules",
        "Load YARA rules as a string into the YARA-X engine.",
        loader::RuleLoader {},
    );

    let settings = settings::Settings::new("default");
    settings.register_group("yara-x-binja", "yara-x-binja");

    let default_path = format!(".{}rules", std::path::MAIN_SEPARATOR);

    let properties = json!(
        {
            "title": "Directory for YARA Rules",
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
