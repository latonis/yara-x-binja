use binaryninja::{binaryview::BinaryView, command::register};

fn run(_view: &BinaryView) {
    dbg!("AHH");
}

#[no_mangle]
pub extern "C" fn UIPluginInit() -> bool {
    register(
        "YARA-X Matches in Binja",
        "Tag YARA rule hits in bndb via YARA-X engine.",
        run,
    );
    true
}
