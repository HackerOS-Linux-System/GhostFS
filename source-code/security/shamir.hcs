use rand::RngCore;
use crate::error::HfsError;

const SHARE_MAGIC: &str = "GFSHAMIR1";

#[derive(Clone, Debug)]
pub struct Share {
    pub index:     u8,
    pub threshold: u8,
    pub total:     u8,
    pub ys:        [u8; 32],
}

impl Share {
    pub fn serialize(&self) -> String {
        format!("{}:{}:{}:{}:{}", SHARE_MAGIC, self.threshold, self.total, self.index, hex::encode(self.ys))
    }

    pub fn deserialize(s: &str) -> Result<Self, HfsError> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        if parts.len() != 5 || parts[0] != SHARE_MAGIC {
            return Err(HfsError::InvalidArgument(
                "Not a valid GhostFS Shamir share file (bad magic/format)".into()
            ));
        }
        let threshold: u8 = parts[1].parse()
            .map_err(|_| HfsError::InvalidArgument("Invalid threshold in share".into()))?;
        let total: u8 = parts[2].parse()
            .map_err(|_| HfsError::InvalidArgument("Invalid total in share".into()))?;
        let index: u8 = parts[3].parse()
            .map_err(|_| HfsError::InvalidArgument("Invalid index in share".into()))?;
        let ys_bytes = hex::decode(parts[4])
            .map_err(|_| HfsError::InvalidArgument("Invalid hex payload in share".into()))?;
        if ys_bytes.len() != 32 {
            return Err(HfsError::InvalidArgument("Share payload must be 32 bytes".into()));
        }
        let mut ys = [0u8; 32];
        ys.copy_from_slice(&ys_bytes);
        Ok(Self { index, threshold, total, ys })
    }
}

// ── GF(256) arytmetyka (ciało AES: reducing poly x^8+x^4+x^3+x+1 = 0x11B) ──

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a = a.wrapping_shl(1);
        if hi != 0 { a ^= 0x1B; }
        b >>= 1;
    }
    p
}

fn gf_pow(a: u8, mut e: u32) -> u8 {
    let mut result: u8 = 1;
    let mut base = a;
    while e > 0 {
        if e & 1 == 1 { result = gf_mul(result, base); }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

/// Odwrotność multiplikatywna w GF(256): a^(255-1) = a^254 = a^-1 dla a≠0
/// (grupa multiplikatywna GF(256)\{0} ma rząd 255, więc a^255=1).
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "gf_inv(0) is undefined");
    gf_pow(a, 254)
}

/// Podziel 32-bajtowy sekret na `n` części, z których dowolne `k` odtwarza
/// oryginał (a k-1 lub mniej — matematycznie zero informacji o sekrecie).
pub fn split(secret: &[u8; 32], n: u8, k: u8) -> Result<Vec<Share>, HfsError> {
    if k < 2 {
        return Err(HfsError::InvalidArgument("Threshold must be at least 2 (use 1 share = no point in splitting)".into()));
    }
    if k > n {
        return Err(HfsError::InvalidArgument(format!("Threshold ({}) cannot exceed total shares ({})", k, n)));
    }
    if n == 0 || n > 254 {
        return Err(HfsError::InvalidArgument("Total shares must be between 1 and 254 (x=0 is reserved for the secret itself)".into()));
    }

    let mut rng = rand::thread_rng();
    // Dla każdego z 32 bajtów sekretu: niezależny losowy wielomian stopnia
    // k-1, którego wyraz wolny to TEN bajt sekretu.
    let mut all_coeffs: Vec<Vec<u8>> = Vec::with_capacity(32);
    for byte_idx in 0..32 {
        let mut coeffs = Vec::with_capacity(k as usize);
        coeffs.push(secret[byte_idx]);
        for _ in 1..k {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coeffs.push(buf[0]);
        }
        all_coeffs.push(coeffs);
    }

    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let mut ys = [0u8; 32];
        for byte_idx in 0..32 {
            let mut y: u8 = 0;
            let mut x_pow: u8 = 1;
            for &c in &all_coeffs[byte_idx] {
                y ^= gf_mul(c, x_pow);
                x_pow = gf_mul(x_pow, x);
            }
            ys[byte_idx] = y;
        }
        shares.push(Share { index: x, threshold: k, total: n, ys });
    }
    Ok(shares)
}

/// Zrekonstruuj sekret z co najmniej `threshold` części (nadmiarowe części
/// ponad próg są ignorowane — używane są pierwsze `threshold` po indeksie).
pub fn combine(shares: &[Share]) -> Result<[u8; 32], HfsError> {
    if shares.is_empty() {
        return Err(HfsError::InvalidArgument("No shares provided".into()));
    }
    let threshold = shares[0].threshold;
    if shares.iter().any(|s| s.threshold != threshold) {
        return Err(HfsError::InvalidArgument("Shares have inconsistent threshold values — mixed share sets?".into()));
    }

    let mut unique: Vec<&Share> = Vec::new();
    for s in shares {
        if !unique.iter().any(|u| u.index == s.index) {
            unique.push(s);
        }
    }
    if (unique.len() as u8) < threshold {
        return Err(HfsError::InvalidArgument(format!(
            "Need at least {} distinct shares, got {}", threshold, unique.len()
        )));
    }
    unique.truncate(threshold as usize);

    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        let points: Vec<(u8, u8)> = unique.iter().map(|s| (s.index, s.ys[byte_idx])).collect();
        secret[byte_idx] = lagrange_at_zero(&points);
    }
    Ok(secret)
}

/// Interpolacja Lagrange'a w x=0 nad GF(256) — standardowy krok
/// rekonstrukcji Shamira. Odejmowanie w GF(2^n) to XOR, więc (0 - x_j) = x_j
/// i (x_i - x_j) = x_i XOR x_j.
fn lagrange_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret: u8 = 0;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j { continue; }
            num = gf_mul(num, xj);
            den = gf_mul(den, xi ^ xj);
        }
        let term = gf_mul(yi, gf_mul(num, gf_inv(den)));
        secret ^= term;
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_combine_roundtrip() {
        let secret: [u8; 32] = std::array::from_fn(|i| (i * 7 + 3) as u8);
        let shares = split(&secret, 5, 3).unwrap();
        // Dowolne 3 z 5 powinny wystarczyć.
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine(&subset).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn below_threshold_fails() {
        let secret = [42u8; 32];
        let shares = split(&secret, 5, 3).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        assert!(combine(&subset).is_err());
    }
}
