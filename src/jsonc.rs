//! Minimal JSONC (JSON with comments and trailing commas) parser that keeps
//! line/column positions for every value, so findings can point at the exact
//! spot in `devcontainer.json`.

use std::fmt;

/// 1-based line and column (column counted in characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

/// A parsed JSON value with its source position.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub pos: Pos,
    /// Line of the last character of this value.
    pub end_line: usize,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Node>),
    Object(Vec<Member>),
}

/// An object member: key, key position and value.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub key: String,
    pub key_pos: Pos,
    pub value: Node,
}

/// A comment found while parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct Comment {
    pub pos: Pos,
    pub text: String,
    /// True if only whitespace precedes the comment on its line.
    pub own_line: bool,
}

/// Parsed document: root value plus all comments.
#[derive(Debug, Clone)]
pub struct Document {
    pub root: Node,
    pub comments: Vec<Comment>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub pos: Pos,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.pos.line, self.pos.col, self.msg)
    }
}

impl std::error::Error for ParseError {}

impl Node {
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self.value {
            Value::Bool(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Node]> {
        match &self.value {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&[Member]> {
        match &self.value {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    /// Look up an object member (last one wins, like JSON.parse).
    pub fn member(&self, key: &str) -> Option<&Member> {
        self.as_object()?.iter().rev().find(|m| m.key == key)
    }
    pub fn get(&self, key: &str) -> Option<&Node> {
        self.member(key).map(|m| &m.value)
    }
    /// Visit every string value in the tree.
    pub fn walk_strings<'a>(&'a self, f: &mut dyn FnMut(&'a Node, &'a str)) {
        match &self.value {
            Value::String(s) => f(self, s),
            Value::Array(a) => a.iter().for_each(|n| n.walk_strings(f)),
            Value::Object(m) => m.iter().for_each(|m| m.value.walk_strings(f)),
            _ => {}
        }
    }
}

/// Parse a JSONC document.
pub fn parse(src: &str) -> Result<Document, ParseError> {
    let mut p = Parser {
        chars: src.chars().collect(),
        i: 0,
        line: 1,
        col: 1,
        comments: Vec::new(),
        line_has_code: false,
    };
    let src_has_bom = p.chars.first() == Some(&'\u{feff}');
    if src_has_bom {
        p.i = 1;
    }
    p.skip_ws()?;
    let root = p.value(0)?;
    p.skip_ws()?;
    if p.i < p.chars.len() {
        return Err(p.err("unexpected trailing content"));
    }
    Ok(Document {
        root,
        comments: p.comments,
    })
}

struct Parser {
    chars: Vec<char>,
    i: usize,
    line: usize,
    col: usize,
    comments: Vec<Comment>,
    line_has_code: bool,
}

const MAX_DEPTH: usize = 256;

impl Parser {
    fn pos(&self) -> Pos {
        Pos {
            line: self.line,
            col: self.col,
        }
    }
    fn err(&self, msg: &str) -> ParseError {
        ParseError {
            pos: self.pos(),
            msg: msg.into(),
        }
    }
    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
            self.line_has_code = false;
        } else {
            self.col += 1;
            if !c.is_whitespace() {
                self.line_has_code = true;
            }
        }
        Some(c)
    }
    fn skip_ws(&mut self) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('/') => {
                    let start = self.pos();
                    let own_line = !self.line_has_code;
                    let had_code = self.line_has_code;
                    match self.chars.get(self.i + 1) {
                        Some('/') => {
                            self.bump();
                            self.bump();
                            let mut text = String::new();
                            while let Some(c) = self.peek() {
                                if c == '\n' {
                                    break;
                                }
                                text.push(c);
                                self.bump();
                            }
                            self.comments.push(Comment {
                                pos: start,
                                text,
                                own_line,
                            });
                            self.line_has_code = had_code;
                        }
                        Some('*') => {
                            self.bump();
                            self.bump();
                            let mut text = String::new();
                            loop {
                                match self.bump() {
                                    None => return Err(self.err("unterminated block comment")),
                                    Some('*') if self.peek() == Some('/') => {
                                        self.bump();
                                        break;
                                    }
                                    Some(c) => text.push(c),
                                }
                            }
                            let same_line = self.line == start.line;
                            self.comments.push(Comment {
                                pos: start,
                                text,
                                own_line,
                            });
                            self.line_has_code = same_line && had_code;
                        }
                        _ => return Err(self.err("unexpected '/'")),
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn expect(&mut self, c: char) -> Result<(), ParseError> {
        if self.peek() == Some(c) {
            self.bump();
            Ok(())
        } else {
            Err(self.err(&format!("expected '{c}'")))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Node, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        let pos = self.pos();
        self.line_has_code = true;
        let value = match self.peek() {
            None => return Err(self.err("unexpected end of input")),
            Some('{') => self.object(depth)?,
            Some('[') => self.array(depth)?,
            Some('"') => Value::String(self.string()?),
            Some('t') => self.word("true", Value::Bool(true))?,
            Some('f') => self.word("false", Value::Bool(false))?,
            Some('n') => self.word("null", Value::Null)?,
            Some(c) if c == '-' || c.is_ascii_digit() => self.number()?,
            Some(c) => return Err(self.err(&format!("unexpected character '{c}'"))),
        };
        let end_line = if self.col == 1 && self.line > pos.line {
            self.line - 1
        } else {
            self.line
        };
        Ok(Node {
            pos,
            end_line,
            value,
        })
    }
    fn word(&mut self, w: &str, v: Value) -> Result<Value, ParseError> {
        for expected in w.chars() {
            if self.peek() != Some(expected) {
                return Err(self.err(&format!("invalid literal, expected '{w}'")));
            }
            self.bump();
        }
        Ok(v)
    }
    fn number(&mut self) -> Result<Value, ParseError> {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E') {
                s.push(c);
                self.bump();
            } else {
                break;
            }
        }
        s.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| self.err(&format!("invalid number '{s}'")))
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return Err(self.err("unterminated string")),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let cp = self.hex4()?;
                        if (0xD800..0xDC00).contains(&cp) {
                            if self.bump() == Some('\\') && self.bump() == Some('u') {
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                            } else {
                                return Err(self.err("invalid surrogate pair"));
                            }
                        } else {
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                    }
                    _ => return Err(self.err("invalid escape")),
                },
                Some(c) => out.push(c),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut v = 0;
        for _ in 0..4 {
            let d = self
                .bump()
                .and_then(|c| c.to_digit(16))
                .ok_or_else(|| self.err("invalid \\u escape"))?;
            v = v * 16 + d;
        }
        Ok(v)
    }
    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect('[')?;
        let mut items = Vec::new();
        loop {
            self.skip_ws()?;
            if self.peek() == Some(']') {
                self.bump();
                return Ok(Value::Array(items));
            }
            items.push(self.value(depth + 1)?);
            self.skip_ws()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {}
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect('{')?;
        let mut members = Vec::new();
        loop {
            self.skip_ws()?;
            match self.peek() {
                Some('}') => {
                    self.bump();
                    return Ok(Value::Object(members));
                }
                Some('"') => {}
                _ => return Err(self.err("expected string key or '}'")),
            }
            let key_pos = self.pos();
            self.line_has_code = true;
            let key = self.string()?;
            self.skip_ws()?;
            self.expect(':')?;
            self.skip_ws()?;
            let value = self.value(depth + 1)?;
            members.push(Member {
                key,
                key_pos,
                value,
            });
            self.skip_ws()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {}
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_and_trailing_commas() {
        let src =
            "// top\n{\n  /* block */ \"a\": [1, 2,], // trailing\n  \"b\": {\"c\": true,},\n}\n";
        let d = parse(src).unwrap();
        assert_eq!(d.comments.len(), 3);
        assert!(d.comments[0].own_line);
        assert!(!d.comments[2].own_line);
        let a = d.root.member("a").unwrap();
        assert_eq!(a.key_pos, Pos { line: 3, col: 15 });
        assert_eq!(a.value.as_array().unwrap().len(), 2);
        assert_eq!(
            d.root.get("b").unwrap().get("c").unwrap().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn positions_and_escapes() {
        let d = parse("{\"k\":\n  \"v\\u00e9\\n\"}").unwrap();
        let v = d.root.get("k").unwrap();
        assert_eq!(v.pos, Pos { line: 2, col: 3 });
        assert_eq!(v.as_str(), Some("vé\n"));
    }

    #[test]
    fn errors_have_positions() {
        let e = parse("{\n  \"a\": tru\n}").unwrap_err();
        assert_eq!(e.pos.line, 2);
        assert!(parse("{\"a\": 1} x").is_err());
        assert!(parse("/* open").is_err());
    }

    #[test]
    fn trailing_comments_after_punctuation_are_not_own_line() {
        let d = parse("{\n  \"a\": [1], // t1\n  \"b\": {}, /* t2 */\n  // own\n  \"c\": 1\n}")
            .unwrap();
        let own: Vec<bool> = d.comments.iter().map(|c| c.own_line).collect();
        assert_eq!(own, vec![false, false, true]);
    }

    #[test]
    fn rejects_bad_surrogates() {
        assert!(parse(r#""\ud800\u0041""#).is_err());
        assert_eq!(
            parse(r#""\ud83d\ude00""#).unwrap().root.as_str(),
            Some("\u{1F600}")
        );
    }

    #[test]
    fn end_line_spans_multiline_values() {
        let d = parse("{\n \"a\": [\n  1,\n  2\n ]\n}").unwrap();
        let a = d.root.get("a").unwrap();
        assert_eq!((a.pos.line, a.end_line), (2, 5));
    }
}
