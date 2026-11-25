use std::collections::{BTreeMap, BTreeSet};

const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UNBIASED_LIMIT: usize = (256 / ALPHABET.len()) * ALPHABET.len();

struct Characters {
    reader: blake3::OutputReader,
    block: [u8; 64],
    position: usize,
}

impl Characters {
    fn new(content: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(content);
        let block = [0; 64];
        Self {
            reader: hasher.finalize_xof(),
            block,
            position: block.len(),
        }
    }

    fn next(&mut self) -> char {
        loop {
            if self.position == self.block.len() {
                self.reader.fill(&mut self.block);
                self.position = 0;
            }
            let byte = usize::from(self.block[self.position]);
            self.position += 1;
            // 248 is divisible by 62. Discarding 248..=255 gives every
            // character four equally likely byte values.
            if byte < UNBIASED_LIMIT {
                return ALPHABET[byte % ALPHABET.len()] as char;
            }
        }
    }
}

// Content must be deduplicated before allocation. All generated tags in a
// collision extend together, so the result does not depend on input order.
pub fn allocate<'a>(
    contents: impl IntoIterator<Item = &'a [u8]>,
    reserved: &BTreeSet<String>,
) -> Vec<String> {
    let mut sources: Vec<_> = contents.into_iter().map(Characters::new).collect();
    let mut tags = vec![String::new(); sources.len()];
    let mut pending: Vec<_> = (0..sources.len()).collect();

    while !pending.is_empty() {
        for &index in &pending {
            tags[index].push(sources[index].next());
        }
        let mut groups = BTreeMap::<&str, Vec<usize>>::new();
        for index in pending.drain(..) {
            groups.entry(&tags[index]).or_default().push(index);
        }
        for (tag, indices) in groups {
            if indices.len() > 1 || reserved.contains(tag) {
                pending.extend(indices);
            }
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collision_extends_every_member_and_leaves_unique_tags_short() {
        let contents: Vec<_> = (0..40)
            .map(|index| format!("ruleset {index}").into_bytes())
            .collect();
        let empty = BTreeSet::new();
        let initial: Vec<_> = contents
            .iter()
            .map(|content| allocate([content.as_slice()], &empty).pop().unwrap())
            .collect();
        let allocated = allocate(contents.iter().map(Vec::as_slice), &empty);
        let mut found_collision = false;
        let mut found_unique = false;
        for (index, tag) in allocated.iter().enumerate() {
            let prefix = &initial[index];
            assert!(tag.starts_with(prefix));
            if initial.iter().filter(|item| *item == prefix).count() > 1 {
                assert!(tag.len() > 1);
                found_collision = true;
            } else {
                assert_eq!(tag, prefix);
                found_unique = true;
            }
        }
        assert!(found_collision && found_unique);
        assert_eq!(
            allocated.iter().collect::<BTreeSet<_>>().len(),
            contents.len()
        );
        let reversed = allocate(contents.iter().rev().map(Vec::as_slice), &empty);
        assert!(allocated.iter().eq(reversed.iter().rev()));
    }

    #[test]
    fn characters_follow_the_reference_xof_even_past_a_buffer_boundary() {
        let input = b"ruleset condition";
        let mut reader = blake3::Hasher::new().update(input).finalize_xof();
        let mut raw = [0; 256];
        reader.fill(&mut raw);
        let expected: String = raw
            .into_iter()
            .filter(|byte| usize::from(*byte) < 248)
            .take(128)
            .map(|byte| ALPHABET[usize::from(byte) % 62] as char)
            .collect();
        assert!(raw.into_iter().any(|byte| byte >= 248));
        let mut stream = Characters::new(input);
        let actual: String = (0..128).map(|_| stream.next()).collect();
        assert_eq!(actual, expected);
    }
}
