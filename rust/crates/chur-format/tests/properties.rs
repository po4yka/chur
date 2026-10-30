//! Property tests for the canonical codec and the waveform record.
//!
//! The unit tests pin boundary values, and the fuzz targets prove that a
//! parser never panics. These cover what neither does: arbitrary values and
//! field orders, and the §8 rule of `CANONICAL_ENCODING_V1.md` that a decoder
//! accepts only the one encoding of a value. Every accepted input, including
//! one with a byte changed, must re-encode to exactly the bytes that were read.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chur_core::Id;
use chur_core::limits::media::{DURATION_MS_MAX, WAVEFORM_BUCKETS_MAX};
use chur_core::status::ChurStatus;
use chur_format::codec::{Reader, Writer};
use chur_format::waveform::Waveform;
use proptest::prelude::*;

/// The parser bound for variable elements in these properties.
const VARIABLE_MAX: u32 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Field {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bool(bool),
    Presence(bool),
    Id([u8; 16]),
    Variable(Vec<u8>),
    Text(String),
}

fn field() -> impl Strategy<Value = Field> {
    prop_oneof![
        any::<u8>().prop_map(Field::U8),
        any::<u16>().prop_map(Field::U16),
        any::<u32>().prop_map(Field::U32),
        any::<u64>().prop_map(Field::U64),
        any::<bool>().prop_map(Field::Bool),
        any::<bool>().prop_map(Field::Presence),
        any::<[u8; 16]>()
            .prop_filter("the all-zero identifier is reserved", |bytes| *bytes
                != [0; 16])
            .prop_map(Field::Id),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(Field::Variable),
        ".{0,16}".prop_map(Field::Text),
    ]
}

fn write(fields: &[Field]) -> Vec<u8> {
    write_with_starts(fields).0
}

/// The encoding and the offset at which each field begins.
fn write_with_starts(fields: &[Field]) -> (Vec<u8>, Vec<usize>) {
    let mut writer = Writer::default();
    let mut starts = Vec::with_capacity(fields.len());
    for field in fields {
        starts.push(writer.len());
        match field {
            Field::U8(value) => drop(writer.u8(*value)),
            Field::U16(value) => drop(writer.u16(*value)),
            Field::U32(value) => drop(writer.u32(*value)),
            Field::U64(value) => drop(writer.u64(*value)),
            Field::Bool(value) => drop(writer.bool(*value)),
            Field::Presence(value) => drop(writer.presence(*value)),
            Field::Id(bytes) => drop(writer.id(&Id::new(*bytes).unwrap())),
            Field::Variable(bytes) => drop(writer.variable(bytes).unwrap()),
            Field::Text(text) => drop(writer.string(text).unwrap()),
        }
    }
    (writer.as_slice().to_vec(), starts)
}

/// A replacement byte. Half are the values next to the canonical boolean and
/// presence bytes, which a uniform byte almost never produces.
fn replacement() -> impl Strategy<Value = u8> {
    prop_oneof![0u8..=3, any::<u8>()]
}

/// Reads `bytes` with the layout of `shape`, as a record decoder would.
fn read(bytes: &[u8], shape: &[Field]) -> chur_core::Result<Vec<Field>> {
    let mut reader = Reader::new(bytes, ChurStatus::ObjectCorrupt);
    let mut fields = Vec::with_capacity(shape.len());
    for slot in shape {
        fields.push(match slot {
            Field::U8(_) => Field::U8(reader.u8()?),
            Field::U16(_) => Field::U16(reader.u16()?),
            Field::U32(_) => Field::U32(reader.u32()?),
            Field::U64(_) => Field::U64(reader.u64()?),
            Field::Bool(_) => Field::Bool(reader.bool()?),
            Field::Presence(_) => Field::Presence(reader.presence()?),
            Field::Id(_) => Field::Id(*reader.id()?.as_bytes()),
            Field::Variable(_) => Field::Variable(reader.variable(VARIABLE_MAX)?.to_vec()),
            Field::Text(_) => Field::Text(reader.string(VARIABLE_MAX)?.to_owned()),
        });
    }
    reader.finish()?;
    Ok(fields)
}

fn waveform() -> impl Strategy<Value = Waveform> {
    let duration = 0..=u32::try_from(DURATION_MS_MAX).unwrap();
    let peaks = prop::collection::vec(any::<u8>(), 1..=WAVEFORM_BUCKETS_MAX);
    (duration, peaks).prop_map(|(duration_ms, peaks)| Waveform::new(duration_ms, peaks).unwrap())
}

proptest! {
    #[test]
    fn any_field_sequence_round_trips(fields in prop::collection::vec(field(), 0..16)) {
        prop_assert_eq!(read(&write(&fields), &fields).unwrap(), fields);
    }

    #[test]
    fn any_waveform_round_trips(record in waveform()) {
        prop_assert_eq!(Waveform::decode(&record.encode()).unwrap(), record);
    }
}

proptest! {
    // One changed byte rarely lands on a field that can be non-canonical, so
    // these properties take more cases than the round trips.
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn an_accepted_mutation_is_the_canonical_encoding_of_what_was_read(
        fields in prop::collection::vec(field(), 1..16),
        field_at in any::<prop::sample::Index>(),
        byte_at in any::<prop::sample::Index>(),
        at_field_start in any::<bool>(),
        replacement in replacement(),
    ) {
        let (mut bytes, starts) = write_with_starts(&fields);
        prop_assume!(!bytes.is_empty());
        // A field's first byte is its whole value for a boolean or presence
        // byte and the high length byte for a variable element.
        let at = if at_field_start { starts[field_at.index(starts.len())] } else { byte_at.index(bytes.len()) };
        prop_assume!(at < bytes.len());
        bytes[at] = replacement;
        if let Ok(decoded) = read(&bytes, &fields) {
            prop_assert_eq!(write(&decoded), bytes);
        }
    }

    #[test]
    fn an_accepted_waveform_is_the_canonical_encoding_of_its_value(
        record in waveform(),
        byte_at in any::<prop::sample::Index>(),
        in_head in any::<bool>(),
        replacement in replacement(),
    ) {
        let mut bytes = record.encode();
        let span = if in_head { chur_format::waveform::HEAD_LEN } else { bytes.len() };
        let at = byte_at.index(span);
        bytes[at] = replacement;
        if let Ok(decoded) = Waveform::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes);
        }
    }
}
