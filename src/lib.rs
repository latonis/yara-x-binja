use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register, Command},
    logger::Logger,
    tags::TagType,
};
use bstr::BStr;
use log::{info, LevelFilter};

struct MyCommand;

impl Command for MyCommand {
    fn action(&self, view: &BinaryView) {
        let mut buf = Vec::new();

        view.read_into_vec(&mut buf, view.start(), view.len());

        info!("Read in");

        let mut compiler = yara_x::Compiler::new();

        compiler
            .add_source(
                r#"
                rule lorem_ipsum {
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
        let tt = view.create_tag_type("YARA-X Matches", "👹");
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
        "YARA-X Matches in Binja",
        "Tag YARA rule hits in bndb via the YARA-X engine.",
        MyCommand {},
    );

    info!("yara-x-binja initialized successfully");

    true
}
