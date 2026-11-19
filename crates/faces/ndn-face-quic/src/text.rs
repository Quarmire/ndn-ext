//! Words another device sent, made safe to show.
//!
//! A close reason is chosen by the device that closes the link. Anything
//! that device is, hostile included, may put in it: line breaks and escape
//! sequences that forge log lines or repaint a terminal, bidirectional
//! controls that reorder what a UI shows, zero-width characters that hide
//! text, or a page of words meant to persuade a user. What this crate hands
//! up of such text ([`LinkError::Refused`](crate::LinkError)) has been through
//! [`sanitize_peer_text`]: no control or invisible characters, runs of
//! whitespace collapsed to one space, at most [`PEER_TEXT_MAX`] characters.

/// The most characters of a peer's words that are kept; a longer text ends in
/// `…` within this bound.
pub const PEER_TEXT_MAX: usize = 512;

/// What a truncated text ends with.
const ELLIPSIS: char = '…';

/// Characters that show nothing or change how the text around them is
/// shown, besides the control characters (`char::is_control`): the
/// bidirectional controls, zero-width and invisible-operator characters,
/// the interlinear annotation marks and the tag characters.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// `text` without control and invisible characters (tab, newline, carriage
/// return and every Unicode space count as spaces), runs of spaces collapsed
/// to one, and no space at either end. Not bounded; see [`bounded_text`].
pub fn clean_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
        } else if c.is_control() || is_invisible(c) {
            // dropped: it joins the words around it
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    out
}

/// `text` if it has at most `max` characters, else its first `max - 1`
/// characters and `…`.
pub fn bounded_text(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_owned(),
        Some(_) if max == 0 => String::new(),
        Some(_) => {
            let keep = text
                .char_indices()
                .nth(max - 1)
                .map_or(text.len(), |(i, _)| i);
            let mut out = String::with_capacity(keep + ELLIPSIS.len_utf8());
            out.push_str(&text[..keep]);
            out.push(ELLIPSIS);
            out
        }
    }
}

/// Another device's words, as this crate hands them up: [`clean_text`], then
/// [`bounded_text`] to [`PEER_TEXT_MAX`].
pub fn sanitize_peer_text(text: &str) -> String {
    bounded_text(&clean_text(text), PEER_TEXT_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words_are_unchanged() {
        let s = "not a device of a namespace I hold";
        assert_eq!(sanitize_peer_text(s), s);
        assert_eq!(
            sanitize_peer_text("héllo wörld 日本語"),
            "héllo wörld 日本語"
        );
    }

    #[test]
    fn controls_escapes_and_line_breaks_go() {
        assert_eq!(
            sanitize_peer_text("a\r\nb\x1b[31mred\x07\x00\u{85}\u{7f}c\u{2028}d\te"),
            "a b[31mred c d e"
        );
    }

    #[test]
    fn bidi_and_invisible_characters_go() {
        assert_eq!(
            sanitize_peer_text("pay\u{202E}elbaliava\u{2066}x\u{2069}\u{200B}\u{FEFF}\u{200F}!"),
            "payelbaliavax!"
        );
    }

    #[test]
    fn whitespace_collapses_and_ends_are_trimmed() {
        assert_eq!(sanitize_peer_text("  a \n\n \u{a0} b  "), "a b");
        assert_eq!(sanitize_peer_text("\n\x1b\n"), "");
    }

    #[test]
    fn a_long_text_ends_in_an_ellipsis_within_the_bound() {
        let long = "word ".repeat(1000);
        let s = sanitize_peer_text(&long);
        assert_eq!(s.chars().count(), PEER_TEXT_MAX);
        assert!(s.ends_with('…'));
        let exact = "x".repeat(PEER_TEXT_MAX);
        assert_eq!(sanitize_peer_text(&exact), exact);
        assert_eq!(bounded_text("日本語です", 3), "日本…");
        assert_eq!(bounded_text("abc", 0), "");
    }
}
