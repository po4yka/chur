//! The portable catalog export, `CatalogExportV1`, of ADR-0068.
//!
//! A version 2 backup package carries the catalog as this logical stream and
//! never as SQLCipher pages. `docs/format/CATALOG_SCHEMA_V1.md` §15 forbids the
//! pages in a package: they carry one client's page format and SQLCipher build
//! options, and no other build is required to read them. The stream carries
//! what the pages mean instead: every row of every ordinary catalog table, in
//! one order, with one encoding per value.
//!
//! ```text
//! CatalogExportV1 =
//!     export_version:u16              0x0001
//!     catalog_format_version:u16
//!     catalog_generation:u64
//!     table_count:u32
//!     table[table_count]
//!
//! table =
//!     table_name:string               ascending byte order across tables
//!     column_count:u16
//!     column_name:string[column_count]  in declared column order
//!     row_count:u64
//!     value[row_count * column_count]   row by row, in primary-key order
//!
//! value =
//!     0x01                            NULL
//!   | 0x02 integer:bytes[8]           SQLite INTEGER, two's complement, big-endian
//!   | 0x03 text:string                strict UTF-8, u32 length
//!   | 0x04 blob:variable bytes        u32 length
//! ```
//!
//! `CANONICAL_ENCODING_V1.md` §2 forbids signed integers unless a focused
//! specification defines them. This one does: an INTEGER is the eight bytes of
//! its 64-bit two's complement form, most significant first. A floating-point
//! value has no encoding, and no catalog column holds one.
//!
//! The stream is cut into chunks for sealing. Every chunk but the last holds
//! exactly [`bounds::CATALOG_EXPORT_CHUNK_LEN`] bytes and the last holds 1 to
//! that many, so one stream has exactly one chunk sequence. A value may cross a
//! chunk boundary; the reader joins chunks as it parses and holds at most one
//! chunk and one value at a time.

use chur_core::{Result, bail, ensure, limits::backup as bounds};
use zeroize::Zeroizing;

use crate::constants::CATALOG_EXPORT_VERSION_V1;

/// The `value_type` of a NULL.
pub const VALUE_NULL: u8 = 0x01;
/// The `value_type` of a SQLite INTEGER.
pub const VALUE_INTEGER: u8 = 0x02;
/// The `value_type` of strict UTF-8 text.
pub const VALUE_TEXT: u8 = 0x03;
/// The `value_type` of a blob.
pub const VALUE_BLOB: u8 = 0x04;

/// The fixed head of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportHeader {
    /// The catalog schema version the rows belong to.
    pub catalog_format_version: u16,
    /// The catalog generation the export was taken at.
    pub catalog_generation: u64,
    /// The tables that follow.
    pub table_count: u32,
}

/// The head of one table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableHeader {
    /// The table name.
    pub name: String,
    /// The column names, in declared order.
    pub columns: Vec<String>,
    /// The rows that follow.
    pub row_count: u64,
}

/// One column value of one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// A SQLite INTEGER.
    Integer(i64),
    /// Strict UTF-8 text.
    Text(Zeroizing<String>),
    /// A blob.
    Blob(Zeroizing<Vec<u8>>),
}

/// Whether a table or column name has the only shape the export admits.
///
/// Every catalog identifier is lower-case ASCII, digits, and underscores, and
/// `CATALOG_SCHEMA_V1.md` §16.5 keeps user labels out of the DDL. Refusing any
/// other byte also means an imported name can never change the SQL it is
/// quoted into.
#[must_use]
pub fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= bounds::CATALOG_EXPORT_NAME_MAX as usize
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writes the stream and hands each sealed-size chunk to `sink`.
///
/// `sink` receives the chunk bytes and whether the chunk is the last. A chunk
/// is passed on as not last only when more bytes already follow it, so a
/// stream whose length is a multiple of the chunk size still ends with a full
/// last chunk rather than with an empty one.
pub struct ExportWriter<F: FnMut(&[u8], bool) -> Result<()>> {
    sink: F,
    buffer: Zeroizing<Vec<u8>>,
}

impl<F: FnMut(&[u8], bool) -> Result<()>> ExportWriter<F> {
    /// Starts a stream with its header.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::InvalidInput`](chur_core::ChurStatus::InvalidInput) for a table count outside its
    /// bound.
    pub fn new(sink: F, header: &ExportHeader) -> Result<Self> {
        ensure!(
            (1..=bounds::CATALOG_EXPORT_TABLES_MAX).contains(&header.table_count),
            InvalidInput,
            "a catalog export holds 1 to 256 tables"
        );
        let mut writer = Self {
            sink,
            buffer: Zeroizing::new(Vec::with_capacity(bounds::CATALOG_EXPORT_CHUNK_LEN + 64)),
        };
        writer.push(&CATALOG_EXPORT_VERSION_V1.to_be_bytes())?;
        writer.push(&header.catalog_format_version.to_be_bytes())?;
        writer.push(&header.catalog_generation.to_be_bytes())?;
        writer.push(&header.table_count.to_be_bytes())?;
        Ok(writer)
    }

    /// Starts one table.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::InvalidInput`](chur_core::ChurStatus::InvalidInput) for a name [`name_valid`] refuses
    /// or a column count outside its bound.
    pub fn table(&mut self, table: &TableHeader) -> Result<()> {
        let count = u16::try_from(table.columns.len()).unwrap_or(u16::MAX);
        ensure!(
            (1..=bounds::CATALOG_EXPORT_COLUMNS_MAX).contains(&count),
            InvalidInput,
            "an exported table holds 1 to 64 columns"
        );
        self.name(&table.name)?;
        self.push(&count.to_be_bytes())?;
        for column in &table.columns {
            self.name(column)?;
        }
        self.push(&table.row_count.to_be_bytes())
    }

    /// Writes one NULL.
    ///
    /// # Errors
    ///
    /// Returns the errors of the sink.
    pub fn null(&mut self) -> Result<()> {
        self.push(&[VALUE_NULL])
    }

    /// Writes one INTEGER.
    ///
    /// # Errors
    ///
    /// Returns the errors of the sink.
    pub fn integer(&mut self, value: i64) -> Result<()> {
        self.push(&[VALUE_INTEGER])?;
        self.push(&value.to_be_bytes())
    }

    /// Writes one text value from its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::InvalidInput`](chur_core::ChurStatus::InvalidInput) for bytes that are not strict UTF-8
    /// or that exceed the value bound.
    pub fn text(&mut self, value: &[u8]) -> Result<()> {
        ensure!(
            std::str::from_utf8(value).is_ok(),
            InvalidInput,
            "an exported text value is not UTF-8"
        );
        self.push(&[VALUE_TEXT])?;
        self.variable(value)
    }

    /// Writes one blob.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::InvalidInput`](chur_core::ChurStatus::InvalidInput) above the value bound.
    pub fn blob(&mut self, value: &[u8]) -> Result<()> {
        self.push(&[VALUE_BLOB])?;
        self.variable(value)
    }

    /// Ends the stream and hands the last chunk to the sink.
    ///
    /// # Errors
    ///
    /// Returns the errors of the sink.
    pub fn finish(mut self) -> Result<()> {
        (self.sink)(&self.buffer, true)
    }

    fn name(&mut self, name: &str) -> Result<()> {
        ensure!(
            name_valid(name),
            InvalidInput,
            "an exported table or column name has a shape the export refuses"
        );
        self.variable(name.as_bytes())
    }

    fn variable(&mut self, value: &[u8]) -> Result<()> {
        let length = u32::try_from(value.len())
            .ok()
            .filter(|length| *length <= bounds::CATALOG_EXPORT_VALUE_MAX)
            .ok_or_else(|| {
                chur_core::err!(
                    InvalidInput,
                    "an exported value exceeds the catalog export bound"
                )
            })?;
        self.push(&length.to_be_bytes())?;
        self.push(value)
    }

    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let chunk = bounds::CATALOG_EXPORT_CHUNK_LEN;
        let mut rest = bytes;
        while !rest.is_empty() {
            // A full chunk is passed on only once a byte beyond it exists, so
            // the chunk that ends the stream is always the one `finish` sends.
            if self.buffer.len() == chunk {
                (self.sink)(&self.buffer, false)?;
                self.buffer.clear();
            }
            let take = rest.len().min(chunk - self.buffer.len());
            self.buffer.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Supplies the opened chunks of one stream, in order.
pub trait ChunkSource {
    /// The next chunk, or `None` after the last.
    ///
    /// # Errors
    ///
    /// Returns the source's own failure, such as an AEAD rejection.
    fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>>;
}

/// Parses the stream from a [`ChunkSource`].
///
/// Every failure of the stream's own shape is `VAULT_CORRUPT`: the stream was
/// sealed by the holder of the vault root, so a shape the writer cannot produce
/// is damage or forgery, not a caller error.
pub struct ExportReader<S: ChunkSource> {
    source: S,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    ended: bool,
}

impl<S: ChunkSource> ExportReader<S> {
    /// Starts reading and parses the header.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::UnsupportedVersion`](chur_core::ChurStatus::UnsupportedVersion) for an unknown
    /// `export_version`, and [`ChurStatus::VaultCorrupt`](chur_core::ChurStatus::VaultCorrupt) for a short stream or
    /// a table count outside its bound.
    pub fn new(source: S) -> Result<(Self, ExportHeader)> {
        let mut reader = Self {
            source,
            buffer: Zeroizing::new(Vec::new()),
            position: 0,
            ended: false,
        };
        let export_version = u16::from_be_bytes(reader.fixed()?);
        ensure!(
            export_version == CATALOG_EXPORT_VERSION_V1,
            UnsupportedVersion,
            "the catalog export declares an unsupported export version"
        );
        let header = ExportHeader {
            catalog_format_version: u16::from_be_bytes(reader.fixed()?),
            catalog_generation: u64::from_be_bytes(reader.fixed()?),
            table_count: u32::from_be_bytes(reader.fixed()?),
        };
        ensure!(
            (1..=bounds::CATALOG_EXPORT_TABLES_MAX).contains(&header.table_count),
            VaultCorrupt,
            "the catalog export declares a table count outside its bound"
        );
        Ok((reader, header))
    }

    /// Parses the head of the next table.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultCorrupt`](chur_core::ChurStatus::VaultCorrupt) for a short stream, a name
    /// [`name_valid`] refuses, or a column count outside its bound.
    pub fn table(&mut self) -> Result<TableHeader> {
        let name = self.name()?;
        let count = u16::from_be_bytes(self.fixed()?);
        ensure!(
            (1..=bounds::CATALOG_EXPORT_COLUMNS_MAX).contains(&count),
            VaultCorrupt,
            "an exported table declares a column count outside its bound"
        );
        let mut columns = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            columns.push(self.name()?);
        }
        let row_count = u64::from_be_bytes(self.fixed()?);
        Ok(TableHeader {
            name,
            columns,
            row_count,
        })
    }

    /// Parses one value.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultCorrupt`](chur_core::ChurStatus::VaultCorrupt) for a short stream, an unallocated
    /// `value_type`, a value above its bound, or text that is not UTF-8.
    pub fn value(&mut self) -> Result<Value> {
        let [value_type] = self.fixed::<1>()?;
        match value_type {
            VALUE_NULL => Ok(Value::Null),
            VALUE_INTEGER => Ok(Value::Integer(i64::from_be_bytes(self.fixed()?))),
            VALUE_TEXT => {
                // The buffer becomes the string in place, so the text exists
                // once in memory and that one copy is wiped on drop.
                let mut bytes = self.variable()?;
                match String::from_utf8(std::mem::take(&mut *bytes)) {
                    Ok(text) => Ok(Value::Text(Zeroizing::new(text))),
                    Err(error) => {
                        drop(Zeroizing::new(error.into_bytes()));
                        bail!(VaultCorrupt, "an exported text value is not UTF-8")
                    }
                }
            }
            VALUE_BLOB => Ok(Value::Blob(self.variable()?)),
            _ => bail!(
                VaultCorrupt,
                "the catalog export carries an unallocated value type"
            ),
        }
    }

    /// Requires the stream to end exactly here.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultCorrupt`](chur_core::ChurStatus::VaultCorrupt) when bytes or chunks follow.
    pub fn finish(mut self) -> Result<()> {
        ensure!(
            self.position == self.buffer.len(),
            VaultCorrupt,
            "the catalog export carries bytes after its last table"
        );
        if !self.ended {
            ensure!(
                self.source.next_chunk()?.is_none(),
                VaultCorrupt,
                "the catalog export carries chunks after its last table"
            );
        }
        Ok(())
    }

    fn name(&mut self) -> Result<String> {
        let bytes = self.variable()?;
        let name = std::str::from_utf8(&bytes)
            .ok()
            .filter(|name| name_valid(name))
            .ok_or_else(|| {
                chur_core::err!(
                    VaultCorrupt,
                    "the catalog export carries a table or column name it refuses"
                )
            })?;
        Ok(name.to_owned())
    }

    fn variable(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let length = u32::from_be_bytes(self.fixed()?);
        ensure!(
            length <= bounds::CATALOG_EXPORT_VALUE_MAX,
            VaultCorrupt,
            "the catalog export carries a value above its bound"
        );
        self.take(length as usize)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Takes `length` bytes, joining chunks as needed. The output grows with
    /// the bytes that arrive, so a forged length cannot make it allocate more
    /// than the stream holds.
    fn take(&mut self, length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            length.min(bounds::CATALOG_EXPORT_CHUNK_LEN),
        ));
        while out.len() < length {
            if self.position == self.buffer.len() {
                ensure!(
                    !self.ended,
                    VaultCorrupt,
                    "the catalog export ends inside a value"
                );
                match self.source.next_chunk()? {
                    Some(chunk) => {
                        self.buffer = chunk;
                        self.position = 0;
                    }
                    None => {
                        self.ended = true;
                        bail!(VaultCorrupt, "the catalog export ends inside a value");
                    }
                }
            }
            let take = (length - out.len()).min(self.buffer.len() - self.position);
            out.extend_from_slice(&self.buffer[self.position..self.position + take]);
            self.position += take;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use chur_core::ChurStatus;

    /// Chunks held in memory, with the final flag the writer gave each.
    struct Chunks(std::vec::IntoIter<Vec<u8>>);

    impl ChunkSource for Chunks {
        fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.next().map(Zeroizing::new))
        }
    }

    fn write(blob_length: usize) -> Vec<(Vec<u8>, bool)> {
        let mut chunks = Vec::new();
        let header = ExportHeader {
            catalog_format_version: 15,
            catalog_generation: 9,
            table_count: 1,
        };
        let mut writer = ExportWriter::new(
            |bytes: &[u8], last: bool| {
                chunks.push((bytes.to_vec(), last));
                Ok(())
            },
            &header,
        )
        .unwrap();
        writer
            .table(&TableHeader {
                name: "notes".into(),
                columns: vec!["id".into(), "body".into(), "data".into(), "gone".into()],
                row_count: 1,
            })
            .unwrap();
        writer.integer(-2).unwrap();
        writer.text("тест".as_bytes()).unwrap();
        writer.blob(&vec![0x5a; blob_length]).unwrap();
        writer.null().unwrap();
        writer.finish().unwrap();
        chunks
    }

    fn read(chunks: Vec<Vec<u8>>) -> Result<(ExportHeader, TableHeader, Vec<Value>)> {
        let (mut reader, header) = ExportReader::new(Chunks(chunks.into_iter()))?;
        let table = reader.table()?;
        let mut values = Vec::new();
        for _ in 0..table.columns.len() {
            values.push(reader.value()?);
        }
        reader.finish()?;
        Ok((header, table, values))
    }

    #[test]
    fn a_stream_round_trips_across_chunk_boundaries() {
        let chunks = write(bounds::CATALOG_EXPORT_CHUNK_LEN + 10);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0.len(), bounds::CATALOG_EXPORT_CHUNK_LEN);
        assert!(!chunks[0].1 && chunks[1].1);
        let (header, table, values) =
            read(chunks.into_iter().map(|(bytes, _)| bytes).collect()).unwrap();
        assert_eq!(header.catalog_generation, 9);
        assert_eq!(table.name, "notes");
        assert_eq!(values[0], Value::Integer(-2));
        assert_eq!(values[1], Value::Text(Zeroizing::new("тест".into())));
        assert_eq!(values[3], Value::Null);
    }

    /// A stream whose length is a multiple of the chunk size ends with a full
    /// last chunk, never with an empty one.
    #[test]
    fn an_exact_multiple_ends_with_a_full_last_chunk() {
        // Header 16, table head 4+5+2+(4+2)+(4+4)+(4+4)+(4+4)+8 = 49, values
        // 9 + 1+4+8 + 1+4+n + 1 = 28 + n.
        let fixed = 16 + 49 + 28;
        let chunks = write(bounds::CATALOG_EXPORT_CHUNK_LEN - fixed);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0.len(), bounds::CATALOG_EXPORT_CHUNK_LEN);
        assert!(chunks[0].1);
    }

    #[test]
    fn a_truncated_or_extended_stream_is_refused() {
        let chunks: Vec<Vec<u8>> = write(10).into_iter().map(|(bytes, _)| bytes).collect();
        let mut short = chunks.clone();
        short[0].pop();
        assert_eq!(read(short).unwrap_err().status(), ChurStatus::VaultCorrupt);

        let mut long = chunks.clone();
        long[0].push(0);
        assert_eq!(read(long).unwrap_err().status(), ChurStatus::VaultCorrupt);

        let mut extra = chunks;
        extra.push(vec![0]);
        assert_eq!(read(extra).unwrap_err().status(), ChurStatus::VaultCorrupt);
    }

    #[test]
    fn a_name_outside_the_identifier_shape_is_refused() {
        assert!(name_valid("object_streams"));
        for name in ["", "Objects", "a b", "x\"y", "o;drop"] {
            assert!(!name_valid(name), "{name}");
        }
        let mut chunks: Vec<Vec<u8>> = write(1).into_iter().map(|(bytes, _)| bytes).collect();
        // The first byte of the table name, after the 16-byte header and the
        // name's length prefix.
        chunks[0][20] = b'N';
        assert_eq!(read(chunks).unwrap_err().status(), ChurStatus::VaultCorrupt);
    }

    #[test]
    fn an_unknown_version_or_value_type_is_refused() {
        let chunks: Vec<Vec<u8>> = write(1).into_iter().map(|(bytes, _)| bytes).collect();
        let mut version = chunks.clone();
        version[0][1] = 0x02;
        assert_eq!(
            read(version).unwrap_err().status(),
            ChurStatus::UnsupportedVersion
        );
        let mut value_type = chunks;
        value_type[0][16 + 49] = 0x05;
        assert_eq!(
            read(value_type).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
    }
}
