//! Rasterize `assets/logo-mark.svg` into PNGs at build time.
//!
//! Writes them to `OUT_DIR` so the running binary can `include_bytes!` the 256px
//! PNG for its window icon (no external tooling, no extra files to ship). Also
//! writes the larger sizes for packaging (.icns / .ico generation).

use std::path::Path;

fn rasterize(svg_path: &Path, out_path: &Path, size: u32) {
    let svg_bytes = std::fs::read(svg_path).expect("read SVG");
    let tree = usvg::Tree::from_data(&svg_bytes, &usvg::Options::default())
        .expect("parse SVG");
    let view = tree.size();
    let scale = size as f32 / view.width().max(view.height());
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("alloc pixmap");
    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    let file = std::fs::File::create(out_path).expect("create png");
    let w = &mut std::io::BufWriter::new(file);
    let mut encoder = png::Encoder::new(w, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    writer.write_image_data(pixmap.data()).expect("png data");
}

fn main() {
    let svg = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/logo-mark.svg");
    println!("cargo:rerun-if-changed=assets/logo-mark.svg");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let out = Path::new(&out_dir);
    for &size in &[16, 32, 64, 128, 256, 512] {
        rasterize(&svg, &out.join(format!("logo-{size}.png")), size);
    }
}
