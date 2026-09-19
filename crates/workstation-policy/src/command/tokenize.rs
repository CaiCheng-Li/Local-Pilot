//! Tokenizers for `cmd.exe` command lines and Windows argument quoting.

/// A single simple command inside a `cmd.exe` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Segment {
    pub tokens: Vec<String>,
    pub redirects: Vec<Redirect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub target: String,
    pub append: bool,
    pub input: bool,
}

/// Split a `cmd.exe` command line into simple commands at `&`, `&&`, `|`,
/// `||`, `(` and `)`, honouring double quotes and `^` escapes, and extracting
/// `>`, `>>`, `2>`, `<` redirections.
pub fn split_cmd(line: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut cur = Segment::default();
    let mut tok = String::new();
    let mut tok_started = false;
    let mut in_quote = false;
    let mut pending_redirect: Option<(bool, bool)> = None; // (append, input)
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    let flush_tok = |tok: &mut String,
                     tok_started: &mut bool,
                     cur: &mut Segment,
                     pending: &mut Option<(bool, bool)>| {
        if *tok_started {
            let t = std::mem::take(tok);
            if let Some((append, input)) = pending.take() {
                if !t.starts_with('&') {
                    cur.redirects.push(Redirect {
                        target: t,
                        append,
                        input,
                    });
                }
            } else {
                cur.tokens.push(t);
            }
            *tok_started = false;
        }
    };

    while i < chars.len() {
        let c = chars[i];
        if in_quote {
            if c == '"' {
                in_quote = false;
            } else {
                tok.push(c);
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_quote = true;
                tok_started = true;
            }
            '^' => {
                if i + 1 < chars.len() {
                    tok.push(chars[i + 1]);
                    tok_started = true;
                    i += 1;
                }
            }
            ' ' | '\t' | '\r' | '\n' => {
                flush_tok(&mut tok, &mut tok_started, &mut cur, &mut pending_redirect);
                if c == '\n' && (!cur.tokens.is_empty() || !cur.redirects.is_empty()) {
                    segments.push(std::mem::take(&mut cur));
                }
            }
            '&' | '|' | '(' | ')' => {
                flush_tok(&mut tok, &mut tok_started, &mut cur, &mut pending_redirect);
                if !cur.tokens.is_empty() || !cur.redirects.is_empty() {
                    segments.push(std::mem::take(&mut cur));
                }
                if (c == '&' || c == '|') && i + 1 < chars.len() && chars[i + 1] == c {
                    i += 1;
                }
            }
            '>' | '<' => {
                // A preceding lone fd digit belongs to the redirection.
                if tok_started && (tok == "1" || tok == "2") {
                    tok.clear();
                    tok_started = false;
                } else {
                    flush_tok(&mut tok, &mut tok_started, &mut cur, &mut pending_redirect);
                }
                let append = c == '>' && i + 1 < chars.len() && chars[i + 1] == '>';
                if append {
                    i += 1;
                }
                // `2>&1` style duplication: skip the handle reference.
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    i += 1;
                    while i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                        i += 1;
                    }
                } else {
                    pending_redirect = Some((append, c == '<'));
                }
            }
            _ => {
                tok.push(c);
                tok_started = true;
            }
        }
        i += 1;
    }
    flush_tok(&mut tok, &mut tok_started, &mut cur, &mut pending_redirect);
    if !cur.tokens.is_empty() || !cur.redirects.is_empty() {
        segments.push(cur);
    }
    for s in &mut segments {
        if let Some(first) = s.tokens.first_mut()
            && let Some(stripped) = first.strip_prefix('@')
        {
            *first = stripped.to_string();
        }
        s.tokens.retain(|t| !t.is_empty());
    }
    segments
}

/// Quote one argument for `CreateProcess` using the MSVCRT/`CommandLineToArgvW` rules.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\x0b' || c == '"')
    {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Split a Windows command line the way `CommandLineToArgvW` does.
pub fn split_windows_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut started = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                let mut n = 0;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        cur.push('"');
                        i += 1;
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                started = true;
                continue;
            }
            '"' => {
                if in_quote && i + 1 < chars.len() && chars[i + 1] == '"' {
                    cur.push('"');
                    i += 1;
                } else {
                    in_quote = !in_quote;
                }
                started = true;
            }
            ' ' | '\t' if !in_quote => {
                if started {
                    args.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            _ => {
                cur.push(c);
                started = true;
            }
        }
        i += 1;
    }
    if started {
        args.push(cur);
    }
    args
}

/// Normalise a program token to a lowercase base name without extension.
pub fn program_name(token: &str) -> String {
    let base = token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".com", ".ps1"] {
        if let Some(s) = base.strip_suffix(ext) {
            return s.to_string();
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_cmd_segments_and_redirects() {
        let s = split_cmd(
            r#"echo hi > "C:\out dir\x.txt" && del /q C:\tmp\a.txt | more & type ^"quoted^" 2>&1"#,
        );
        assert_eq!(s.len(), 4, "{s:?}");
        assert_eq!(s[0].tokens, vec!["echo", "hi"]);
        assert_eq!(s[0].redirects[0].target, r"C:\out dir\x.txt");
        assert_eq!(s[1].tokens, vec!["del", "/q", r"C:\tmp\a.txt"]);
        assert_eq!(s[2].tokens, vec!["more"]);
        assert_eq!(s[3].tokens, vec!["type", "\"quoted\""]);
        assert!(s[3].redirects.is_empty());
        let s = split_cmd("dir >> log.txt");
        assert!(s[0].redirects[0].append);
        let s = split_cmd("@git status");
        assert_eq!(s[0].tokens[0], "git");
    }

    #[test]
    fn quoting_roundtrips() {
        for a in [
            "simple",
            "with space",
            "quote\"inside",
            r"trailing\",
            r"C:\Program Files\x\",
            "",
        ] {
            let q = quote_arg(a);
            assert_eq!(split_windows_args(&q), vec![a.to_string()], "{a:?} -> {q}");
        }
    }

    #[test]
    fn program_names() {
        assert_eq!(program_name(r"C:\Program Files\Git\cmd\git.exe"), "git");
        assert_eq!(program_name("NPM.CMD"), "npm");
        assert_eq!(program_name("gh"), "gh");
    }
}
