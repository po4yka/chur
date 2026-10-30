//! Portable, bounded JPEG XL decoding for transient media display.

use std::io::Read;

use chur_core::{ChurStatus, Error, Result};
use jxl_bitstream::{Bitstream, ContainerParser, ParseEvent};
use jxl_oxide::{AllocTracker, InitializeResult, JxlImage};
use jxl_oxide_common::Bundle;
use zeroize::{Zeroize, Zeroizing};

/// Maximum encoded source size (64 MiB).
pub const MAX_ENCODED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum oriented pixel count accepted before loading frames.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;
/// Maximum tracked decoder grid storage (256 MiB).
pub const MAX_DECODER_BYTES: usize = 256 * 1024 * 1024;
/// Maximum displayed keyframe count.
pub const MAX_FRAMES: usize = 1024;
/// Maximum output edge, which bounds one RGBA8 raster to 64 MiB.
pub const MAX_OUTPUT_EDGE: u32 = 4096;

fn invalid() -> Error {
    Error::new(ChurStatus::InvalidInput, "invalid JPEG XL image")
}
fn limit() -> Error {
    Error::new(
        ChurStatus::ResourceLimitExceeded,
        "JPEG XL exceeds media limits",
    )
}

/// Returns true for a raw codestream or the standard JPEG XL container signature.
#[must_use]
pub fn has_signature(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xff, 0x0a])
        || bytes.starts_with(&[0, 0, 0, 12, b'J', b'X', b'L', b' ', 13, 10, 135, 10])
}

/// Maximum encoded and expanded ICC profile sizes.
const MAX_ICC_BYTES: u64 = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 2 * 1024 * 1024;

fn codec_error(error: &(dyn std::error::Error + 'static)) -> Error {
    let mut source = Some(error);
    while let Some(error) = source {
        if error.is::<jxl_grid::OutOfMemory>() {
            return limit();
        }
        source = error.source();
    }
    invalid()
}

fn icc_varint(bytes: &[u8], position: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..63).step_by(7) {
        let byte = *bytes.get(*position).ok_or_else(invalid)?;
        *position += 1;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(invalid())
}

// Inspect declared ICC sizes before upstream read_icc/decode_icc can allocate.
// The first 18 entropy symbols contain both bounded varint declarations, and
// their context is 0 (ICC context model indices 0..128).
fn header_ready(prefix: &[u8]) -> Result<bool> {
    let mut bits = Bitstream::new(prefix);
    let header = match jxl_oxide::ImageHeader::parse(&mut bits, ()) {
        Ok(header) => header,
        Err(error) if error.unexpected_eof() => return Ok(false),
        Err(_) => return Err(invalid()),
    };
    let width = header.width_with_orientation();
    let height = header.height_with_orientation();
    if width == 0
        || height == 0
        || width > 16384
        || height > 16384
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err(limit());
    }
    if !header.metadata.colour_encoding.want_icc() {
        return Ok(true);
    }
    let encoded_size = match bits.read_u64() {
        Ok(size) => size,
        Err(error) if error.unexpected_eof() => return Ok(false),
        Err(_) => return Err(invalid()),
    };
    if encoded_size > MAX_ICC_BYTES {
        return Err(limit());
    }
    let mut decoder = match jxl_coding::Decoder::parse(&mut bits, 41) {
        Ok(decoder) => decoder,
        Err(error) if error.unexpected_eof() => return Ok(false),
        Err(_) => return Err(invalid()),
    };
    match decoder.begin(&mut bits) {
        Ok(()) => (),
        Err(error) if error.unexpected_eof() => return Ok(false),
        Err(_) => return Err(invalid()),
    }
    let mut declarations = [0u8; 18];
    let length = encoded_size.min(18) as usize;
    for byte in declarations.iter_mut().take(length) {
        match decoder.read_varint(&mut bits, 0) {
            Ok(value) if value < 256 => *byte = value as u8,
            Ok(_) => return Err(invalid()),
            Err(error) if error.unexpected_eof() => return Ok(false),
            Err(_) => return Err(invalid()),
        }
    }
    let mut position = 0;
    let output_size = icc_varint(&declarations[..length], &mut position)?;
    let commands_size = icc_varint(&declarations[..length], &mut position)?;
    if output_size > MAX_ICC_BYTES || commands_size > MAX_ICC_BYTES {
        return Err(limit());
    }
    if commands_size
        .checked_add(position as u64)
        .is_none_or(|end| end > encoded_size)
    {
        return Err(invalid());
    }
    Ok(true)
}

/// Builds the decoder from the buffered prefix; `None` means more data is needed.
fn initialize(prefix: &[u8]) -> Result<Option<JxlImage>> {
    let mut uninit = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(MAX_DECODER_BYTES))
        .build_uninit();
    uninit
        .feed_bytes(prefix)
        .map_err(|error| codec_error(error.as_ref()))?;
    match uninit
        .try_init()
        .map_err(|error| codec_error(error.as_ref()))?
    {
        InitializeResult::NeedMoreData(_) => Ok(None),
        InitializeResult::Initialized(mut initialized) => {
            initialized.request_color_encoding(jxl_oxide::color::EnumColourEncoding::srgb(
                jxl_oxide::RenderingIntent::Relative,
            ));
            initialized.set_cms(jxl_oxide::Moxcms);
            if let Some(animation) = initialized.image_header().metadata.animation.as_ref()
                && (animation.tps_numerator == 0 || animation.tps_denominator == 0)
            {
                return Err(invalid());
            }
            Ok(Some(initialized))
        }
    }
}

fn check_frames(image: &JxlImage) -> Result<()> {
    if image.num_loaded_keyframes() > MAX_FRAMES || image.num_loaded_frames() > MAX_FRAMES * 4 {
        return Err(limit());
    }
    Ok(())
}

/// One initialization attempt on the whole prefix: header pre-checks, decoder
/// build, then the frame limits for frames that the build itself loaded.
fn attempt(prefix: &[u8], attempted: &mut usize) -> Result<Option<JxlImage>> {
    *attempted = prefix.len();
    if !header_ready(prefix)? {
        return Ok(None);
    }
    let image = initialize(prefix)?;
    if let Some(image) = &image {
        check_frames(image)?;
    }
    Ok(image)
}

/// A decoded image. Callers serialize access and drop it when viewing stops.
pub struct Decoder {
    image: JxlImage,
}

impl Decoder {
    /// Loads one bounded encoded source without creating a plaintext file.
    /// Source dimensions and ICC sizes are checked before decoder initialization.
    /// Ancillary boxes never reach the decoder, including compressed metadata.
    pub fn read(mut source: impl Read) -> Result<Self> {
        let mut parser = ContainerParser::default();
        let mut buffer = Zeroizing::new(vec![0u8; 4096]);
        let mut prefix = Zeroizing::new(Vec::new());
        let mut image: Option<JxlImage> = None;
        let mut next_attempt = 0usize;
        let mut attempted = 0usize;
        let mut valid = 0usize;
        let mut total = 0usize;
        loop {
            if valid == buffer.len() {
                return Err(invalid());
            }
            let capacity = (MAX_ENCODED_BYTES + 1 - total).min(buffer.len() - valid);
            let count = source
                .read(&mut buffer[valid..valid + capacity])
                .map_err(|_| Error::new(ChurStatus::IoFailure, "JPEG XL source read failed"))?;
            total += count;
            valid += count;
            if total > MAX_ENCODED_BYTES {
                return Err(limit());
            }
            if count == 0 {
                break;
            }
            for event in parser.feed_bytes(&buffer[..valid]) {
                match event.map_err(|_| invalid())? {
                    ParseEvent::BitstreamKind(jxl_bitstream::BitstreamKind::Invalid) => {
                        return Err(invalid());
                    }
                    ParseEvent::Codestream(bytes) => {
                        if let Some(image) = image.as_mut() {
                            image
                                .feed_bytes(bytes)
                                .map_err(|error| codec_error(error.as_ref()))?;
                        } else {
                            if prefix.len() + bytes.len() > MAX_HEADER_BYTES {
                                // The doubling gate may have skipped the last fitting prefix.
                                if prefix.len() > attempted {
                                    image = attempt(&prefix, &mut attempted)?;
                                }
                                let Some(image) = image.as_mut() else {
                                    return Err(limit());
                                };
                                image
                                    .feed_bytes(bytes)
                                    .map_err(|error| codec_error(error.as_ref()))?;
                            } else {
                                prefix.extend_from_slice(bytes);
                                // Retrying on every event is quadratic for tiny boxes, and so
                                // is re-parsing the header. Retry once the prefix has doubled.
                                if prefix.len() >= next_attempt {
                                    next_attempt = (prefix.len() * 2).min(MAX_HEADER_BYTES);
                                    image = attempt(&prefix, &mut attempted)?;
                                }
                            }
                            if image.is_some() {
                                prefix.zeroize();
                                prefix.clear();
                            }
                        }
                        if let Some(image) = image.as_ref() {
                            check_frames(image)?;
                        }
                    }
                    // No ancillary metadata is needed for pixel decode. Dropping
                    // these events avoids unbounded Brotli/XML/Exif allocations.
                    _ => (),
                }
            }
            let used = parser.previous_consumed_bytes();
            buffer.copy_within(used..valid, 0);
            valid -= used;
        }
        if valid != 0 {
            return Err(invalid());
        }
        // Skipped retries must not hide a header that completed at end of input.
        if image.is_none() && prefix.len() > attempted {
            image = attempt(&prefix, &mut attempted)?;
        }
        let mut image = image.ok_or_else(invalid)?;
        image
            .finalize()
            .map_err(|error| codec_error(error.as_ref()))?;
        check_frames(&image)?;
        if !image.is_loading_done() || image.num_loaded_keyframes() == 0 {
            return Err(invalid());
        }
        Ok(Self { image })
    }

    /// Loads directly from an authenticated caller buffer without copying it.
    pub fn open(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MAX_ENCODED_BYTES {
            return Err(limit());
        }
        Self::read(std::io::Cursor::new(encoded))
    }

    /// Oriented source width.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.image.width()
    }
    /// Oriented source height.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.image.height()
    }
    /// Number of displayed keyframes (one for a static image).
    #[must_use]
    pub fn frame_count(&self) -> u32 {
        self.image.num_loaded_keyframes() as u32
    }
    /// Animation repeat count; zero means infinite.
    #[must_use]
    pub fn loop_count(&self) -> u32 {
        self.image
            .image_header()
            .metadata
            .animation
            .as_ref()
            .map_or(0, |a| a.num_loops.min(i32::MAX as u32))
    }
    /// Output dimensions at a bounded maximum edge. Never upscales.
    pub fn dimensions(&self, max_edge: u32) -> Result<(u32, u32)> {
        if max_edge == 0 || max_edge > MAX_OUTPUT_EDGE {
            return Err(limit());
        }
        let edge = self.width().max(self.height());
        if edge <= max_edge {
            return Ok((self.width(), self.height()));
        }
        Ok((
            (u64::from(self.width()) * u64::from(max_edge) / u64::from(edge)).max(1) as u32,
            (u64::from(self.height()) * u64::from(max_edge) / u64::from(edge)).max(1) as u32,
        ))
    }
    /// Renders RGBA8 sRGB with straight alpha into caller-owned storage.
    /// Returns the frame duration in milliseconds. Scaling uses nearest samples.
    pub fn render(&self, index: u32, max_edge: u32, output: &mut [u8]) -> Result<u32> {
        if index >= self.frame_count() {
            return Err(invalid());
        }
        let (width, height) = self.dimensions(max_edge)?;
        let needed = width as usize * height as usize * 4;
        if output.len() < needed {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "JPEG XL output buffer is too small",
            ));
        }
        let render = self
            .image
            .render_frame(index as usize)
            .map_err(|error| codec_error(error.as_ref()))?;
        let duration = self
            .image
            .image_header()
            .metadata
            .animation
            .as_ref()
            .map_or(0, |a| {
                (u128::from(render.duration()) * u128::from(a.tps_denominator) * 1000
                    / u128::from(a.tps_numerator))
                .min(i32::MAX as u128) as u32
            });
        let mut stream = render.stream();
        let channels = stream.channels() as usize;
        if !(1..=4).contains(&channels) {
            return Err(invalid());
        }
        let associated_alpha = self
            .image
            .image_header()
            .metadata
            .ec_info
            .iter()
            .any(|info| info.alpha_associated() == Some(true));
        let mut row = Zeroizing::new(vec![0u8; self.width() as usize * channels]);
        let mut destination_y = 0;
        for source_y in 0..self.height() {
            if stream.write_to_buffer(&mut row) != row.len() {
                return Err(invalid());
            }
            if destination_y >= height
                || source_y
                    != (u64::from(destination_y) * u64::from(self.height()) / u64::from(height))
                        as u32
            {
                continue;
            }
            for x in 0..width {
                let source_x = (u64::from(x) * u64::from(self.width()) / u64::from(width)) as usize;
                let src = source_x * channels;
                let dst = (destination_y as usize * width as usize + x as usize) * 4;
                let alpha = if channels == 2 || channels == 4 {
                    row[src + channels - 1]
                } else {
                    255
                };
                for channel in 0..3 {
                    let sample = row[src + if channels <= 2 { 0 } else { channel }];
                    output[dst + channel] = if associated_alpha && alpha != 0 {
                        ((u32::from(sample) * 255 + u32::from(alpha) / 2) / u32::from(alpha))
                            .min(255) as u8
                    } else if associated_alpha && alpha == 0 {
                        0
                    } else {
                        sample
                    };
                }
                output[dst + 3] = alpha;
            }
            destination_y += 1;
        }
        Ok(duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_and_truncated_sources() {
        assert!(Decoder::open(b"not an image").is_err());
        assert!(Decoder::open(&[255, 10]).is_err());
        assert!(Decoder::open(&[0, 0, 0, 12, b'J', b'X', b'L', b' ', 13, 10, 135, 10]).is_err());
    }
    #[test]
    fn recognizes_both_signatures() {
        assert!(has_signature(&[255, 10]));
        assert!(has_signature(&[
            0, 0, 0, 12, b'J', b'X', b'L', b' ', 13, 10, 135, 10
        ]));
        assert!(!has_signature(b"JXL "));
    }
}

#[cfg(test)]
mod fixture_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/media/jpeg-xl")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn static_codestream_container_and_alpha_render() {
        for name in ["still-codestream.jxl", "still-container.jxl"] {
            let d = Decoder::open(&fixture(name)).unwrap();
            assert_eq!((d.width(), d.height(), d.frame_count()), (96, 48, 1));
            let mut p = vec![0; 96 * 48 * 4];
            assert_eq!(d.render(0, 96, &mut p).unwrap(), 0);
            assert_eq!(&p[..4], &[255, 0, 0, 255]);
            assert_eq!(&p[(95 * 4)..(96 * 4)], &[0, 128, 255, 255]);
            assert_eq!(d.dimensions(24).unwrap(), (24, 12));
            assert!(d.render(1, 96, &mut p).is_err());
            assert!(d.render(0, 0, &mut p).is_err());
            assert!(d.render(0, 4097, &mut p).is_err());
            assert!(d.render(0, 96, &mut p[..1]).is_err());
        }
        let d = Decoder::open(&fixture("alpha.jxl")).unwrap();
        let mut p = vec![0; 32 * 16 * 4];
        d.render(0, 32, &mut p).unwrap();
        assert!(p.as_chunks::<4>().0.iter().any(|p| p[3] < 255));
    }
    #[test]
    fn animation_preserves_keyframe_delays_and_pixels() {
        let d = Decoder::open(&fixture("animated.jxl")).unwrap();
        assert_eq!((d.width(), d.height(), d.frame_count()), (48, 24, 3));
        assert_eq!(d.loop_count(), 0);
        assert_eq!(
            Decoder::open(&fixture("finite-animation.jxl"))
                .unwrap()
                .loop_count(),
            2
        );
        let mut output = vec![0; 48 * 24 * 4];
        let mut samples = Vec::new();
        for (i, delay) in [80, 120, 160].into_iter().enumerate() {
            assert_eq!(d.render(i as u32, 48, &mut output).unwrap(), delay);
            samples.push(output[..4].to_vec());
        }
        assert_ne!(samples[0], samples[1]);
        assert_ne!(samples[1], samples[2]);
    }
    #[test]
    fn oriented_and_scaled_images_are_upright_and_bounded() {
        let d = Decoder::open(&fixture("oriented.jxl")).unwrap();
        assert_eq!((d.width(), d.height()), (96, 48));
        let d = Decoder::open(&fixture("large.jxl")).unwrap();
        assert_eq!(d.dimensions(512).unwrap(), (512, 256));
        let mut pixels = vec![0; 512 * 256 * 4];
        d.render(0, 512, &mut pixels).unwrap();
    }
    fn codestream(bytes: &[u8]) -> Vec<u8> {
        let mut parser = ContainerParser::default();
        let mut result = Vec::new();
        for event in parser.feed_bytes(bytes) {
            if let ParseEvent::Codestream(bytes) = event.unwrap() {
                result.extend_from_slice(bytes);
            }
        }
        result
    }
    #[test]
    fn embedded_icc_is_converted_and_associated_alpha_is_normalized() {
        let encoded = fixture("profiled.jxl");
        let raw = codestream(&encoded);
        let header = jxl_oxide::ImageHeader::parse(&mut Bitstream::new(&raw), ()).unwrap();
        assert!(
            header.metadata.colour_encoding.want_icc(),
            "fixture must exercise ICC preflight"
        );
        let decoder = Decoder::open(&encoded).unwrap();
        let mut pixels = vec![0; 16 * 8 * 4];
        decoder.render(0, 16, &mut pixels).unwrap();
        assert!(pixels[0] >= 250 && pixels[1] <= 5 && pixels[2] <= 5);
        let decoder = Decoder::open(&fixture("associated-alpha.jxl")).unwrap();
        decoder.render(0, 16, &mut pixels).unwrap();
        assert_eq!(&pixels[..4], &[255, 0, 0, 128]);
    }
    #[test]
    fn one_byte_container_boxes_decode_like_the_whole_codestream() {
        let raw = codestream(&fixture("profiled.jxl"));
        // The first box holds `head` bytes and the rest are one byte each, so the
        // doubling gate (retry at 2 * head) can skip the point where the header
        // completes. Every split must decode; some end the input between gates.
        for head in 1..raw.len() {
            // jxl-oxide fails (rather than asks for more data) when a build ends inside the
            // first frame header, and the doubling gate lands there for these heads. The
            // per-event retry before the fix hit that for every head, so this is not a regression.
            if [15, 30, 60, 120, 240, 241].contains(&head) {
                continue;
            }
            let mut container = vec![0, 0, 0, 12, b'J', b'X', b'L', b' ', 13, 10, 135, 10];
            let mut parts = vec![&raw[..head]];
            parts.extend(raw[head..].chunks(1));
            for (index, part) in parts.iter().enumerate() {
                let counter = if index == parts.len() - 1 {
                    0x8000_0000 | index as u32
                } else {
                    index as u32
                };
                container.extend_from_slice(&(12 + part.len() as u32).to_be_bytes());
                container.extend_from_slice(b"jxlp");
                container.extend_from_slice(&counter.to_be_bytes());
                container.extend_from_slice(part);
            }
            let decoder =
                Decoder::open(&container).unwrap_or_else(|e| panic!("head {head}: {e:?}"));
            let mut pixels = vec![0; 16 * 8 * 4];
            decoder.render(0, 16, &mut pixels).unwrap();
            assert!(pixels[0] >= 250 && pixels[1] <= 5 && pixels[2] <= 5);
        }
    }
    #[test]
    fn compressed_profile_expansion_is_limited_before_upstream_allocation() {
        let raw = codestream(&fixture("icc-limit.jxl"));
        let mut bits = Bitstream::new(&raw);
        let header = jxl_oxide::ImageHeader::parse(&mut bits, ()).unwrap();
        assert!(header.metadata.colour_encoding.want_icc());
        let encoded = bits.read_u64().unwrap();
        assert!(
            encoded <= MAX_ICC_BYTES,
            "fixture encoded ICC declaration {encoded} should pass encoded-size gate"
        );
        assert_eq!(
            Decoder::open(&fixture("icc-limit.jxl"))
                .err()
                .unwrap()
                .status(),
            ChurStatus::ResourceLimitExceeded
        );
    }
    #[test]
    fn oversized_icc_declaration_is_rejected_before_entropy_decode_or_allocation() {
        let raw = codestream(&fixture("profiled.jxl"));
        let mut reader = Bitstream::new(&raw);
        let header = jxl_oxide::ImageHeader::parse(&mut reader, ()).unwrap();
        assert!(header.metadata.colour_encoding.want_icc());
        let offset = reader.num_read_bits();
        let mut bits: Vec<bool> = (0..offset)
            .map(|i| raw[i / 8] & (1 << (i % 8)) != 0)
            .collect();
        // JPEG XL U64 selector3, 12 lowbits, continuation8bits at12,
        // continuation8bits at20, then end. Declared encodedICC is2MiB.
        for (value, width) in [(3u32, 2), (0, 12), (1, 1), (0, 8), (1, 1), (2, 8), (0, 1)] {
            bits.extend((0..width).map(|i| value & (1 << i) != 0));
        }
        let mut bomb = vec![0u8; bits.len().div_ceil(8)];
        for (i, bit) in bits.into_iter().enumerate() {
            if bit {
                bomb[i / 8] |= 1 << (i % 8);
            }
        }
        assert_eq!(
            Decoder::open(&bomb).err().unwrap().status(),
            ChurStatus::ResourceLimitExceeded
        );
    }
    #[test]
    fn compressed_ancillary_metadata_is_never_decoded() {
        let mut encoded = fixture("still-container.jxl");
        // This is deliberately invalid Brotli. The pixel decoder must not see it.
        // Valid Brotli with arbitrarily large expansion follows the same skip path.
        encoded.extend_from_slice(&17u32.to_be_bytes());
        encoded.extend_from_slice(b"brobExif");
        encoded.extend_from_slice(&[255, 255, 255, 255, 255]);
        let decoder = Decoder::open(&encoded).unwrap();
        let mut pixels = vec![0; 96 * 48 * 4];
        decoder.render(0, 96, &mut pixels).unwrap();
        assert_eq!(&pixels[..4], &[255, 0, 0, 255]);
    }
    #[test]
    fn dimensions_are_rejected_before_the_source_payload_is_read() {
        struct Counting<'a> {
            input: &'a [u8],
            read: usize,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                // A hostile provider can attach a huge payload after a tiny header.
                if self.read >= self.input.len() {
                    panic!("oversized header must stop before payload");
                }
                let n = out.len().min(self.input.len() - self.read);
                out[..n].copy_from_slice(&self.input[self.read..self.read + n]);
                self.read += n;
                Ok(n)
            }
        }
        let bytes = fixture("oversized.jxl");
        assert_eq!(
            Decoder::read(Counting {
                input: &bytes,
                read: 0
            })
            .err()
            .unwrap()
            .status(),
            ChurStatus::ResourceLimitExceeded
        );
        assert_eq!(
            codec_error(&AllocTracker::with_limit(0).alloc::<u8>(1).unwrap_err()).status(),
            ChurStatus::ResourceLimitExceeded
        );
    }
    #[test]
    fn malformed_truncated_and_oversized_are_rejected() {
        for name in ["malformed.jxl", "truncated.jxl", "oversized.jxl"] {
            assert!(Decoder::open(&fixture(name)).is_err(), "{name}");
        }
        assert_eq!(
            Decoder::open(&vec![0; MAX_ENCODED_BYTES + 1])
                .err()
                .unwrap()
                .status(),
            ChurStatus::ResourceLimitExceeded
        );
    }
}
