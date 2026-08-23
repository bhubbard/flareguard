use std::error::Error;

/// Strips JavaScript-style comments (`//` and `/* ... */`) and trailing commas from JSONC text,
/// producing valid standard JSON.
pub fn clean_jsonc(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut output = String::with_capacity(len);
    let mut i = 0;
    let mut in_string = false;
    let mut is_escaped = false;

    // Step 1: Strip comments while respecting strings
    let mut no_comments = String::with_capacity(len);
    while i < len {
        let ch = chars[i];

        if in_string {
            no_comments.push(ch);
            if is_escaped {
                is_escaped = false;
            } else if ch == '\\' {
                is_escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if ch == '"' {
            in_string = true;
            is_escaped = false;
            no_comments.push(ch);
            i += 1;
            continue;
        }

        // Check for line comment //
        if ch == '/' && i + 1 < len && chars[i + 1] == '/' {
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            if i < len {
                no_comments.push('\n');
                i += 1;
            }
            continue;
        }

        // Check for block comment /* ... */
        if ch == '/' && i + 1 < len && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    no_comments.push('\n'); // Preserve line breaks for line numbering
                }
                i += 1;
            }
            i += 2; // skip */
            continue;
        }

        no_comments.push(ch);
        i += 1;
    }

    // Step 2: Strip trailing commas in objects and arrays
    let nc_chars: Vec<char> = no_comments.chars().collect();
    let nc_len = nc_chars.len();
    let mut j = 0;
    let mut in_str = false;
    let mut esc = false;

    while j < nc_len {
        let ch = nc_chars[j];

        if in_str {
            output.push(ch);
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            j += 1;
            continue;
        }

        if ch == '"' {
            in_str = true;
            esc = false;
            output.push(ch);
            j += 1;
            continue;
        }

        if ch == ',' {
            // Peek ahead to see if the next non-whitespace character is `}` or `]`
            let mut k = j + 1;
            while k < nc_len && nc_chars[k].is_whitespace() {
                k += 1;
            }
            if k < nc_len && (nc_chars[k] == '}' || nc_chars[k] == ']') {
                // Skip the trailing comma
                j += 1;
                continue;
            }
        }

        output.push(ch);
        j += 1;
    }

    output
}

/// Parses JSONC or JSON text into a `serde_json::Value`.
pub fn parse_jsonc(input: &str) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
    let cleaned = clean_jsonc(input);
    let val: serde_json::Value = serde_json::from_str(&cleaned)?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_jsonc_basic() {
        let jsonc = r#"
        {
            // This is a line comment
            "name": "my-worker", /* inline comment */
            "vars": {
                "API_KEY": "https://api.example.com//test", // URL with slashes
                "DEBUG": true,
            },
            "kv_namespaces": [
                {
                    "binding": "MY_KV",
                    "id": "12345",
                },
            ],
        }
        "#;
        let cleaned = clean_jsonc(jsonc);
        let parsed: serde_json::Value = serde_json::from_str(&cleaned).expect("Failed to parse cleaned JSON");
        assert_eq!(parsed["name"], "my-worker");
        assert_eq!(parsed["vars"]["API_KEY"], "https://api.example.com//test");
        assert_eq!(parsed["vars"]["DEBUG"], true);
        assert_eq!(parsed["kv_namespaces"][0]["binding"], "MY_KV");
    }

    #[test]
    fn test_clean_jsonc_nested_trailing_commas() {
        let jsonc = r#"{"a": [1, 2, [3, 4,],], "b": {"c": 1,},}"#;
        let cleaned = clean_jsonc(jsonc);
        let parsed: serde_json::Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(parsed["a"][2][0], 3);
        assert_eq!(parsed["b"]["c"], 1);
    }
}
