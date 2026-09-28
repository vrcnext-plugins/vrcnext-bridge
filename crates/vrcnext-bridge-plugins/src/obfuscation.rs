//! The shape rules: source that has been written so a reviewer cannot read it.
//!
//! [`crate::policy`] answers "does this code reach past `ctx.*`", and it answers it by looking
//! for names. That only works on code a person could have read. A minified bundle, a string of
//! `\x65\x76\x61\x6c` escapes, or a `_0x3a2b[17]` lookup table defeats every rule in that table
//! without hiding anything from the runtime — and the point of the policy was never the grep, it
//! was that a dishonest plugin is obvious in review. So this module refuses source that is
//! *shaped* like something meant not to be read, whatever it turns out to say.
//!
//! Every rule here is deliberately blunt and easy to argue with a diff in hand, because a false
//! positive costs an author a refused install and they deserve a reason they can act on:
//!
//! | Rule | Refused because |
//! | :--- | :--- |
//! | `minified` | a line longer than [`MAX_LINE_CHARS`]; nobody writes one by hand |
//! | `packed source` | the whole file averages [`MAX_MEAN_LINE_CHARS`]+ per line |
//! | `escape sequences` | [`MAX_ESCAPE_RUN`]+ `\xNN`/`\uNNNN` in a row, which only ever spells a word the scanner would otherwise see |
//! | `mangled identifiers` | `_0x` + hex: the signature `javascript-obfuscator` leaves |
//! | `opaque blob` | an unbroken [`MIN_BLOB_CHARS`]-character high-entropy token: a payload, not code |
//! | `invisible characters` | zero-width or bidirectional-override characters, which make the source read differently than it runs |
//!
//! None of this detects obfuscation in general — that is undecidable, and a determined author
//! can write unreadable code in plain ASCII with honest line lengths. What it does is take away
//! the cheap, tool-generated kind, and make the expensive kind look like what it is.
//!
//! Binary assets are the one honest thing this refuses: an icon inlined as a `data:` URI is
//! indistinguishable from a payload to a text scan. That is a deliberate trade — a plugin runs
//! with the page's authority, and "what is in that blob" should never be a question a reviewer
//! has to ask.

use crate::policy::PolicyError;

/// Longest single line. A bundler's output is one line of tens of thousands; a hand-written
/// line with a long string or a wide table stays far below this.
pub const MAX_LINE_CHARS: usize = 1000;

/// Longest mean line, over a file of at least [`MEAN_MIN_LINES`] non-empty lines. Catches a
/// bundle that was wrapped, which no single-line rule would see.
pub const MAX_MEAN_LINE_CHARS: usize = 250;

/// Below this many non-empty lines the mean says nothing, so it is not applied.
pub const MEAN_MIN_LINES: usize = 20;

/// Most `\xNN`/`\uNNNN` escapes in a row. Four spells a short word by accident; eight does not.
pub const MAX_ESCAPE_RUN: usize = 8;

/// Shortest unbroken run of blob characters that is looked at at all.
pub const MIN_BLOB_CHARS: usize = 256;

/// Bits of Shannon entropy per character at which a run stops looking like a name and starts
/// looking like data. Random hex is 4.0, random base64 is 6.0; a long camel-case identifier or
/// a repeated filler is well under this.
pub const MIN_BLOB_ENTROPY: f64 = 3.5;

/// Longest run the entropy is measured over, so a pathological line costs a bounded amount.
const MAX_BLOB_SAMPLE: usize = 4096;

/// Characters a base64, base64url or hex payload is made of. A run is broken by anything else,
/// which is why prose — full of spaces and punctuation — never forms one.
fn is_blob_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// Characters that are never legitimately in a plugin's source.
///
/// The zero-width ones hide text inside identifiers and string literals; the bidirectional
/// overrides reorder what a reviewer sees without changing what the compiler reads, which is the
/// Trojan Source attack. A byte-order mark at the very start of a file is ordinary and is
/// skipped by the caller.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Refuse `text` if it is shaped like generated or hidden code.
///
/// # Errors
///
/// The first [`PolicyError::Violation`], with its 1-based line, named by the table above.
pub fn scan(file: &str, text: &str) -> Result<(), PolicyError> {
    let refuse = |line: usize, rule: &'static str| PolicyError::Violation {
        file: file.to_owned(),
        line,
        rule,
    };

    let mut lines = 0_usize;
    let mut total = 0_usize;
    for (index, line) in text.lines().enumerate() {
        let number = index.saturating_add(1);
        let length = line.chars().count();
        if length > MAX_LINE_CHARS {
            return Err(refuse(number, "minified"));
        }
        // A BOM belongs to the file, not to the first line's content.
        let body = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        if body.chars().any(is_invisible) {
            return Err(refuse(number, "invisible characters"));
        }
        if escape_run(line) > MAX_ESCAPE_RUN {
            return Err(refuse(number, "escape sequences"));
        }
        if has_mangled_identifier(line) {
            return Err(refuse(number, "mangled identifiers"));
        }
        if has_opaque_blob(line) {
            return Err(refuse(number, "opaque blob"));
        }
        if length > 0 {
            lines = lines.saturating_add(1);
            total = total.saturating_add(length);
        }
    }

    // Multiplied rather than divided: the mean is only ever compared, never shown.
    if lines >= MEAN_MIN_LINES && total > lines.saturating_mul(MAX_MEAN_LINE_CHARS) {
        return Err(refuse(1, "packed source"));
    }
    Ok(())
}

/// The longest run of consecutive `\xNN` or `\uNNNN` escapes on `line`.
fn escape_run(line: &str) -> usize {
    let bytes = line.as_bytes();
    let (mut best, mut run, mut index) = (0_usize, 0_usize, 0_usize);
    while index < bytes.len() {
        if let Some(width) = escape_at(bytes, index) {
            run = run.saturating_add(1);
            best = best.max(run);
            index = index.saturating_add(width);
        } else {
            run = 0;
            index = index.saturating_add(1);
        }
    }
    best
}

/// The width of the escape starting at `index`, if one does.
fn escape_at(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'\\') {
        return None;
    }
    let (width, digits) = match bytes.get(index.saturating_add(1)) {
        Some(&b'x') => (4, 2),
        Some(&b'u') => (6, 4),
        _ => return None,
    };
    let start = index.saturating_add(2);
    let end = start.saturating_add(digits);
    let tail = bytes.get(start..end)?;
    tail.iter().all(u8::is_ascii_hexdigit).then_some(width)
}

/// Whether `line` contains `_0x` followed by at least four hex digits.
///
/// This is one tool's output rather than a general property, and it is here because that tool is
/// what almost every obfuscated script in the wild was run through.
fn has_mangled_identifier(line: &str) -> bool {
    line.match_indices("_0x").any(|(at, _)| {
        line.get(at.saturating_add(3)..)
            .unwrap_or("")
            .chars()
            .take(4)
            .filter(char::is_ascii_hexdigit)
            .count()
            == 4
    })
}

/// Whether `line` holds an unbroken run of blob characters that is long enough and random
/// enough to be data rather than a name.
fn has_opaque_blob(line: &str) -> bool {
    let mut run = String::new();
    for c in line.chars().chain(std::iter::once(' ')) {
        if is_blob_char(c) {
            if run.chars().count() < MAX_BLOB_SAMPLE {
                run.push(c);
            }
            continue;
        }
        if run.chars().count() >= MIN_BLOB_CHARS && entropy(&run) >= MIN_BLOB_ENTROPY {
            return true;
        }
        run.clear();
    }
    false
}

/// Shannon entropy of `run` in bits per character, over its own alphabet.
fn entropy(run: &str) -> f64 {
    let mut counts = [0_u32; 128];
    let mut total = 0_u32;
    for byte in run.bytes() {
        if let Some(slot) = counts.get_mut(usize::from(byte)) {
            *slot = slot.saturating_add(1);
            total = total.saturating_add(1);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(total);
    counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0_f64, |bits, count| {
            let p = f64::from(*count) / total;
            bits - p * p.log2()
        })
}

#[cfg(test)]
mod tests;
