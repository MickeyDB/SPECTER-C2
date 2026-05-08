const ARG_TYPE_STRING: u32 = 0;
const ARG_TYPE_INT32: u32 = 1;
const MODULE_MAX_ARGS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleArg {
    String(String),
    Int32(u32),
}

pub fn encode_module_args(args: &[ModuleArg]) -> Result<Vec<u8>, String> {
    if args.len() > MODULE_MAX_ARGS {
        return Err(format!("too many module arguments: {}", args.len()));
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(args.len() as u32).to_le_bytes());

    for arg in args {
        match arg {
            ModuleArg::String(value) => {
                let bytes = value.as_bytes();
                let len = bytes
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| "module string argument too large".to_string())?;
                out.extend_from_slice(&ARG_TYPE_STRING.to_le_bytes());
                out.extend_from_slice(&(len as u32).to_le_bytes());
                out.extend_from_slice(bytes);
                out.push(0);
            }
            ModuleArg::Int32(value) => {
                out.extend_from_slice(&ARG_TYPE_INT32.to_le_bytes());
                out.extend_from_slice(&4u32.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }

    Ok(out)
}

pub fn encode_text_module_args(input: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(input).map_err(|_| {
        "module arguments must be UTF-8 text or pre-encoded MODULE_ARGS".to_string()
    })?;
    let parts = split_module_arg_text(text)?;
    let args = parts.into_iter().map(ModuleArg::String).collect::<Vec<_>>();
    encode_module_args(&args)
}

pub fn normalize_module_args(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return encode_module_args(&[]);
    }
    if looks_like_module_args(input) {
        return Ok(input.to_vec());
    }
    encode_text_module_args(input)
}

pub fn split_module_arg_text(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut chars = input.trim().chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            let should_escape = match quote {
                Some(q) => chars.peek().is_some_and(|next| *next == q || *next == '\\'),
                None => chars.peek().is_some_and(|next| next.is_whitespace()),
            };
            if should_escape {
                escaped = true;
            } else {
                cur.push(ch);
            }
            continue;
        }

        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }

        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }

        if ch.is_whitespace() {
            if !cur.is_empty() {
                args.push(std::mem::take(&mut cur));
            }
            continue;
        }

        cur.push(ch);
    }

    if escaped {
        cur.push('\\');
    }
    if quote.is_some() {
        return Err("unterminated quote in module arguments".to_string());
    }
    if !cur.is_empty() {
        args.push(cur);
    }

    Ok(args)
}

fn looks_like_module_args(input: &[u8]) -> bool {
    if input.len() < 4 {
        return false;
    }

    let count = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
    if count > MODULE_MAX_ARGS {
        return false;
    }

    let mut offset = 4usize;
    for _ in 0..count {
        if input.len().saturating_sub(offset) < 8 {
            return false;
        }
        let _arg_type = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let len = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if len > input.len().saturating_sub(offset) {
            return false;
        }
        offset += len;
    }

    offset == input.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_string_args_with_nul_terminators() {
        let encoded = encode_text_module_args(b"start 250").unwrap();
        assert_eq!(&encoded[..4], &2u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &ARG_TYPE_STRING.to_le_bytes());
        assert_eq!(&encoded[8..12], &6u32.to_le_bytes());
        assert_eq!(&encoded[12..18], b"start\0");
    }

    #[test]
    fn preserves_preencoded_args() {
        let encoded = encode_module_args(&[
            ModuleArg::String("status".to_string()),
            ModuleArg::Int32(250),
        ])
        .unwrap();
        assert_eq!(normalize_module_args(&encoded).unwrap(), encoded);
    }

    #[test]
    fn splits_quoted_args() {
        assert_eq!(
            split_module_arg_text(r#"file "C:\Program Files\a.txt" 128"#).unwrap(),
            vec!["file", r#"C:\Program Files\a.txt"#, "128"]
        );
    }
}
