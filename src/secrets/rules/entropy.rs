use std::collections::HashMap;

/// Calculates the Shannon entropy of a string (bits per symbol).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts = HashMap::new();
    let mut total_chars = 0;

    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
        total_chars += 1;
    }

    let total = total_chars as f64;
    let mut entropy = 0.0;

    for &count in char_counts.values() {
        let prob = count as f64 / total;
        entropy -= prob * prob.log2();
    }

    entropy
}

/// Checks if a string has sufficient character diversity to likely be a cryptographic secret/token.
pub fn is_high_entropy_token(s: &str, min_entropy: f64) -> bool {
    if s.len() < 16 {
        return false;
    }

    // Check if it's just all lowercase hex (like git commit hash)
    let is_all_hex = s.chars().all(|c| c.is_ascii_hexdigit());
    let is_all_lower_hex = is_all_hex && s.chars().all(|c| !c.is_ascii_uppercase());
    
    // If it's a 40-char string that is purely lowercase hex, it's very often a git sha or build hash
    if s.len() == 40 && is_all_lower_hex {
        return false;
    }

    let entropy = shannon_entropy(s);
    entropy >= min_entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        // Random 40-char token should have high entropy (> 3.5)
        let token = "Z8-Jb3X9vQ2pL7mK1wR4tY6uI0oP5sD8fG2hJ4kL";
        assert!(shannon_entropy(token) > 3.8);
    }

    #[test]
    fn test_git_sha_filter() {
        // 40 char lowercase hex (git sha)
        let git_sha = "e5ac35da6b107e3240e4f20bf8061266e746e163";
        assert!(!is_high_entropy_token(git_sha, 3.0));
    }
}
