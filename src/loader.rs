use binaryninja::{
    binaryview::BinaryView,
    command::Command,
    interaction::{FormInputBuilder, FormResponses},
    settings,
};
use log::info;

pub struct RuleLoader;

impl Command for RuleLoader {
    fn action(&self, view: &BinaryView) {
        let raw_rules =
            settings::Settings::new("default").get_string("yara-x-binja.rules", Some(view), None);

        let responses = FormInputBuilder::new()
            .multiline_field("YARA Rules", Some(raw_rules.as_str()))
            .get_form_input("Add YARA Rules");

        if responses.len() > 0 {
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
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
