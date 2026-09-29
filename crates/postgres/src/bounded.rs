//! Row- and byte-bounded chunking of streamed rows. A chunk holds at most `rows` rows and
//! `bytes` bytes of wire data; one row larger than `bytes` forms its own chunk, and one larger
//! than `max_row` is refused before it is retained.

/// Transfer bounds for one streamed read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLimits {
    pub rows: usize,
    pub bytes: usize,
    pub max_row: usize,
}

impl Default for ChunkLimits {
    fn default() -> Self {
        Self {
            rows: 4096,
            bytes: 8 << 20,
            max_row: 64 << 20,
        }
    }
}

impl ChunkLimits {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.rows == 0 || self.bytes == 0 || self.max_row == 0 {
            return Err("chunk limits must be positive");
        }
        Ok(())
    }
}

/// A row larger than the per-row bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowTooLarge {
    pub size: usize,
    pub bound: usize,
}

impl std::fmt::Display for RowTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a {} byte row exceeds the {} byte row bound", self.size, self.bound)
    }
}

impl std::error::Error for RowTooLarge {}

/// Accumulates sized items into bounded chunks.
#[derive(Debug)]
pub struct BoundedChunks<T> {
    limits: ChunkLimits,
    pending: Vec<T>,
    bytes: usize,
}

impl<T> BoundedChunks<T> {
    pub fn new(limits: ChunkLimits) -> Self {
        Self {
            limits,
            pending: Vec::new(),
            bytes: 0,
        }
    }

    /// Retain an item of `size` bytes. Returns the completed chunk it displaced, if adding it
    /// would exceed the row or byte bound.
    pub fn push(&mut self, item: T, size: usize) -> Result<Option<(Vec<T>, usize)>, RowTooLarge> {
        if size > self.limits.max_row {
            return Err(RowTooLarge {
                size,
                bound: self.limits.max_row,
            });
        }
        let full = !self.pending.is_empty()
            && (self.pending.len() == self.limits.rows
                || self.bytes.saturating_add(size) > self.limits.bytes);
        let completed = full.then(|| self.take());
        self.pending.push(item);
        self.bytes += size;
        Ok(completed)
    }

    /// Bytes of the retained, not yet completed chunk.
    pub fn pending_bytes(&self) -> usize {
        self.bytes
    }

    /// The final partial chunk, if any.
    pub fn finish(&mut self) -> Option<(Vec<T>, usize)> {
        (!self.pending.is_empty()).then(|| self.take())
    }

    fn take(&mut self) -> (Vec<T>, usize) {
        let bytes = std::mem::take(&mut self.bytes);
        (std::mem::take(&mut self.pending), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1 << 20;

    fn chunk(sizes: &[usize]) -> Result<Vec<usize>, RowTooLarge> {
        let mut chunks = BoundedChunks::new(ChunkLimits::default());
        let mut lengths = Vec::new();
        for (index, size) in sizes.iter().enumerate() {
            if let Some((rows, _)) = chunks.push(index, *size)? {
                lengths.push(rows.len());
            }
        }
        lengths.extend(chunks.finish().map(|(rows, _)| rows.len()));
        Ok(lengths)
    }

    #[test]
    fn bounded_chunks_split_by_rows_and_bytes() {
        assert_eq!(chunk(&[100; 10_000]).unwrap(), [4096, 4096, 1808]);
        assert_eq!(chunk(&[3 * MIB; 3]).unwrap(), [2, 1]);
        assert_eq!(chunk(&[10, 20 * MIB, 10]).unwrap(), [1, 1, 1], "an oversized row travels alone");
        assert_eq!(chunk(&[64 * MIB]).unwrap(), [1], "the row bound is inclusive");
        assert_eq!(chunk(&[]).unwrap(), Vec::<usize>::new(), "no rows, no chunk");
    }

    #[test]
    fn bounded_chunks_refuse_a_row_over_the_bound() {
        assert_eq!(
            chunk(&[10, 70 * MIB]),
            Err(RowTooLarge {
                size: 70 * MIB,
                bound: 64 * MIB
            })
        );
    }

    #[test]
    fn bounded_chunks_report_completed_bytes() {
        let mut chunks = BoundedChunks::new(ChunkLimits {
            rows: 2,
            bytes: 100,
            max_row: 100,
        });
        assert_eq!(chunks.push('a', 40).unwrap(), None);
        assert_eq!(chunks.push('b', 40).unwrap(), None);
        assert_eq!(chunks.pending_bytes(), 80);
        assert_eq!(chunks.push('c', 10).unwrap(), Some((vec!['a', 'b'], 80)));
        assert_eq!(chunks.finish(), Some((vec!['c'], 10)));
        assert_eq!(chunks.finish(), None);
    }
}
