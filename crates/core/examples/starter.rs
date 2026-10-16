//! Prints the video-site starter as JSON, the form the editor receives it in.
fn main() {
    println!("{}", serde_json::to_string(&torus_core::starters::video_site()).unwrap());
}
