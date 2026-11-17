//! A sticky choice among candidates (T-823, RT-2 of the ingest study):
//! weighted rendezvous hashing (HRW) with tiers. For one key, each
//! candidate gets a score from a hash of the key and its id, scaled by its
//! weight; the order is the tier first (the lowest number first), then the
//! score. The same key gives the same order in each process, and a new
//! candidate takes about `1 / (n + 1)` of the keys, each from one other
//! candidate, where a pick at random or by a modulus moves most keys.
//!
//! The hash is SipHash-2-4 with fixed keys: it is stable across versions
//! and processes (the hasher of the standard library is not), and a key of
//! a peer cannot pick a candidate as FNV lets it.

/// One candidate: its id (the text that its score is a hash of), its
/// weight (more than zero; a share of the keys in proportion), and its tier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate<'a> {
    pub id: &'a str,
    pub weight: f64,
    pub tier: u8,
}

/// The indices of `candidates` in their order for `key`: each tier from the
/// lowest, and in each tier the highest score first. A candidate with a
/// weight that is not more than zero (or not a number) comes last.
pub fn rank(key: &[u8], candidates: &[Candidate<'_>]) -> Vec<usize> {
    let mut scored: Vec<(usize, u8, f64)> =
        candidates.iter().enumerate().map(|(i, c)| (i, c.tier, score(key, c))).collect();
    scored.sort_by(|a, b| a.1.cmp(&b.1).then(b.2.total_cmp(&a.2)).then(a.0.cmp(&b.0)));
    scored.into_iter().map(|(i, _, _)| i).collect()
}

/// The first of [`rank`].
pub fn first(key: &[u8], candidates: &[Candidate<'_>]) -> Option<usize> {
    rank(key, candidates).into_iter().next()
}

/// The score of `candidate` for `key`: `-weight / ln(u)`, with `u` in
/// (0, 1) from the hash of the key and the id (the weighted form of HRW).
fn score(key: &[u8], candidate: &Candidate<'_>) -> f64 {
    // A NaN, a weight of zero or less, and an infinity have no score.
    if !candidate.weight.is_finite() || candidate.weight <= 0.0 {
        return f64::NEG_INFINITY;
    }
    let mut input = Vec::with_capacity(key.len() + candidate.id.len() + 1);
    input.extend_from_slice(key);
    // A separator, so that no two pairs give one input.
    input.push(0xff);
    input.extend_from_slice(candidate.id.as_bytes());
    let hash = siphash24(KEYS, &input);
    // 53 bits into (0, 1): never 0 and never 1, so the logarithm is finite.
    let u = ((hash >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    -candidate.weight / u.ln()
}

/// The fixed keys of the hash of a score.
const KEYS: (u64, u64) = (0x706f_6463_7261_7465, 0x732d_7069_636b_2d31);

/// SipHash-2-4 of `data` with the keys `(k0, k1)`.
pub fn siphash24((k0, k1): (u64, u64), data: &[u8]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    let (words, rest) = data.as_chunks::<8>();
    for word in words {
        let m = u64::from_le_bytes(*word);
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    let m = u64::from_le_bytes(last) | ((data.len() as u64 & 0xff) << 56);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
#[path = "pick_tests.rs"]
mod tests;
