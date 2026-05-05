#[unsafe(link_section = ".init_array")]
pub static INITIALIZE: extern "C" fn() = {
    extern "C" fn init() {
        let _ = std::fs::write("/tmp/success.txt", b"so injection successful.");
    }
    init
};
