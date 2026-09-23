use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionScript {
    assignments: BTreeMap<Vec<u8>, Vec<u8>>,
    localize_unlisted: bool,
}

impl VersionScript {
    pub fn parse(input: &[u8]) -> Result<Self, VersionScriptError> {
        if input.contains(&0) {
            return Err(VersionScriptError::ContainsNul);
        }
        let tokens = tokenize(input)?;
        let mut cursor = Cursor::new(tokens);
        let mut assignments = BTreeMap::new();
        let mut versions = BTreeSet::new();
        let mut localize_unlisted = false;

        while !cursor.is_done() {
            let version = cursor.expect_word("version name")?;
            if !versions.insert(version.clone()) {
                return Err(VersionScriptError::DuplicateVersion { version });
            }
            cursor.expect(TokenKind::LBrace, "'{' after version name")?;

            while !cursor.peek_is(TokenKind::RBrace) {
                let clause = cursor.expect_word("global/local clause")?;
                cursor.expect(TokenKind::Colon, "':' after version-script clause")?;
                match clause.as_slice() {
                    b"global" => {
                        let mut saw_symbol = false;
                        loop {
                            if cursor.peek_is(TokenKind::RBrace) || cursor.peek_clause_start() {
                                break;
                            }
                            match cursor.peek() {
                                Some(Token::Star) => {
                                    return Err(VersionScriptError::UnsupportedGlobalWildcard);
                                }
                                Some(Token::Word(_)) => {}
                                Some(token) => {
                                    return Err(VersionScriptError::UnexpectedToken {
                                        expected: "exact global symbol",
                                        found: token.describe(),
                                    });
                                }
                                None => {
                                    return Err(VersionScriptError::UnexpectedEnd {
                                        expected: "exact global symbol",
                                    });
                                }
                            }
                            let symbol = cursor.expect_word("exact global symbol")?;
                            cursor.expect(TokenKind::Semi, "';' after global symbol")?;
                            saw_symbol = true;
                            if assignments.insert(symbol.clone(), version.clone()).is_some() {
                                return Err(VersionScriptError::DuplicateSymbol { symbol });
                            }
                        }
                        if !saw_symbol {
                            return Err(VersionScriptError::EmptyGlobalClause {
                                version: version.clone(),
                            });
                        }
                    }
                    b"local" => {
                        if !cursor.peek_is(TokenKind::Star) {
                            return Err(VersionScriptError::UnsupportedLocalPattern);
                        }
                        cursor.advance();
                        cursor.expect(TokenKind::Semi, "';' after local wildcard")?;
                        localize_unlisted = true;
                    }
                    _ => {
                        return Err(VersionScriptError::UnknownClause { clause });
                    }
                }
            }

            cursor.expect(TokenKind::RBrace, "'}' after version block")?;
            if cursor.peek().is_some() && !cursor.peek_is(TokenKind::Semi) {
                return Err(VersionScriptError::UnsupportedInheritance);
            }
            cursor.expect(TokenKind::Semi, "';' after version block")?;
        }

        if assignments.is_empty() {
            return Err(VersionScriptError::NoGlobalSymbols);
        }

        Ok(Self {
            assignments,
            localize_unlisted,
        })
    }

    pub fn version_for(&self, symbol: &[u8]) -> Option<&[u8]> {
        self.assignments.get(symbol).map(Vec::as_slice)
    }

    pub fn assignments(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.assignments
            .iter()
            .map(|(symbol, version)| (symbol.as_slice(), version.as_slice()))
    }

    pub fn localize_unlisted(&self) -> bool {
        self.localize_unlisted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionScriptError {
    ContainsNul,
    UnterminatedBlockComment,
    UnexpectedEnd {
        expected: &'static str,
    },
    UnexpectedToken {
        expected: &'static str,
        found: &'static str,
    },
    UnknownClause {
        clause: Vec<u8>,
    },
    EmptyGlobalClause {
        version: Vec<u8>,
    },
    UnsupportedGlobalWildcard,
    UnsupportedLocalPattern,
    UnsupportedInheritance,
    DuplicateVersion {
        version: Vec<u8>,
    },
    DuplicateSymbol {
        symbol: Vec<u8>,
    },
    NoGlobalSymbols,
}

impl fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainsNul => write!(f, "version script contains NUL"),
            Self::UnterminatedBlockComment => write!(f, "version script has unterminated block comment"),
            Self::UnexpectedEnd { expected } => {
                write!(f, "version script ended while expecting {expected}")
            }
            Self::UnexpectedToken { expected, found } => {
                write!(f, "version script expected {expected}, found {found}")
            }
            Self::UnknownClause { clause } => write!(
                f,
                "version script clause {:?} is unsupported; bounded scripts accept only global: and local:",
                String::from_utf8_lossy(clause)
            ),
            Self::EmptyGlobalClause { version } => write!(
                f,
                "version block {:?} has an empty global clause",
                String::from_utf8_lossy(version)
            ),
            Self::UnsupportedGlobalWildcard => write!(
                f,
                "version-script global wildcards are unsupported; use exact symbol names"
            ),
            Self::UnsupportedLocalPattern => write!(
                f,
                "bounded version scripts support only local: *;"
            ),
            Self::UnsupportedInheritance => write!(
                f,
                "version-definition inheritance is unsupported in bounded version scripts"
            ),
            Self::DuplicateVersion { version } => write!(
                f,
                "version script defines version {:?} more than once",
                String::from_utf8_lossy(version)
            ),
            Self::DuplicateSymbol { symbol } => write!(
                f,
                "version script assigns symbol {:?} more than once",
                String::from_utf8_lossy(symbol)
            ),
            Self::NoGlobalSymbols => write!(
                f,
                "version script must assign at least one exact global symbol"
            ),
        }
    }
}

impl std::error::Error for VersionScriptError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(Vec<u8>),
    LBrace,
    RBrace,
    Colon,
    Semi,
    Star,
}

impl Token {
    fn kind(&self) -> TokenKind {
        match self {
            Self::Word(_) => TokenKind::Word,
            Self::LBrace => TokenKind::LBrace,
            Self::RBrace => TokenKind::RBrace,
            Self::Colon => TokenKind::Colon,
            Self::Semi => TokenKind::Semi,
            Self::Star => TokenKind::Star,
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Self::Word(_) => "word",
            Self::LBrace => "'{'",
            Self::RBrace => "'}'",
            Self::Colon => "':'",
            Self::Semi => "';'",
            Self::Star => "'*'",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Word,
    LBrace,
    RBrace,
    Colon,
    Semi,
    Star,
}

struct Cursor {
    tokens: Vec<Token>,
    index: usize,
}

impl Cursor {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    fn is_done(&self) -> bool {
        self.index == self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn peek_is(&self, kind: TokenKind) -> bool {
        self.peek().is_some_and(|token| token.kind() == kind)
    }

    fn peek_clause_start(&self) -> bool {
        matches!(
            (self.tokens.get(self.index), self.tokens.get(self.index + 1)),
            (Some(Token::Word(word)), Some(Token::Colon))
                if word.as_slice() == b"global" || word.as_slice() == b"local"
        )
    }

    fn advance(&mut self) {
        self.index += 1;
    }

    fn expect_word(&mut self, expected: &'static str) -> Result<Vec<u8>, VersionScriptError> {
        match self.tokens.get(self.index) {
            Some(Token::Word(word)) => {
                self.index += 1;
                Ok(word.clone())
            }
            Some(token) => Err(VersionScriptError::UnexpectedToken {
                expected,
                found: token.describe(),
            }),
            None => Err(VersionScriptError::UnexpectedEnd { expected }),
        }
    }

    fn expect(
        &mut self,
        kind: TokenKind,
        expected: &'static str,
    ) -> Result<(), VersionScriptError> {
        match self.tokens.get(self.index) {
            Some(token) if token.kind() == kind => {
                self.index += 1;
                Ok(())
            }
            Some(token) => Err(VersionScriptError::UnexpectedToken {
                expected,
                found: token.describe(),
            }),
            None => Err(VersionScriptError::UnexpectedEnd { expected }),
        }
    }
}

fn tokenize(input: &[u8]) -> Result<Vec<Token>, VersionScriptError> {
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < input.len() {
        if input[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }

        if input[index..].starts_with(b"/*") {
            let tail = &input[index + 2..];
            let Some(end) = tail.windows(2).position(|window| window == b"*/") else {
                return Err(VersionScriptError::UnterminatedBlockComment);
            };
            index += 2 + end + 2;
            continue;
        }

        if input[index..].starts_with(b"//") || input[index] == b'#' {
            while index < input.len() && input[index] != b'
' {
                index += 1;
            }
            continue;
        }

        let token = match input[index] {
            b'{' => {
                index += 1;
                Token::LBrace
            }
            b'}' => {
                index += 1;
                Token::RBrace
            }
            b':' => {
                index += 1;
                Token::Colon
            }
            b';' => {
                index += 1;
                Token::Semi
            }
            b'*' => {
                index += 1;
                Token::Star
            }
            _ => {
                let start = index;
                while index < input.len()
                    && !input[index].is_ascii_whitespace()
                    && !matches!(input[index], b'{' | b'}' | b':' | b';' | b'*' | b'#')
                    && !input[index..].starts_with(b"/*")
                    && !input[index..].starts_with(b"//")
                {
                    index += 1;
                }
                if index == start {
                    return Err(VersionScriptError::UnexpectedToken {
                        expected: "version-script token",
                        found: "unsupported byte",
                    });
                }
                Token::Word(input[start..index].to_vec())
            }
        };
        tokens.push(token);
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::{VersionScript, VersionScriptError};

    #[test]
    fn parses_multiple_exact_global_blocks_and_local_wildcard() {
        let script = VersionScript::parse(
            b"VERS_1 { global: old_api; }; VERS_2 { global: current_api; local: *; };",
        )
        .unwrap();

        assert_eq!(script.version_for(b"old_api"), Some(b"VERS_1".as_slice()));
        assert_eq!(
            script.version_for(b"current_api"),
            Some(b"VERS_2".as_slice())
        );
        assert!(script.localize_unlisted());
    }

    #[test]
    fn accepts_comments() {
        let script = VersionScript::parse(
            b"/* provider ABI */ VERS_1 { global: public_api; // exact export
 local: *; };",
        )
        .unwrap();
        assert_eq!(
            script.version_for(b"public_api"),
            Some(b"VERS_1".as_slice())
        );
    }

    #[test]
    fn rejects_inheritance_and_global_wildcards() {
        assert_eq!(
            VersionScript::parse(b"VERS_2 { global: api; } VERS_1;"),
            Err(VersionScriptError::UnsupportedInheritance)
        );
        assert_eq!(
            VersionScript::parse(b"VERS_1 { global: *; };"),
            Err(VersionScriptError::UnsupportedGlobalWildcard)
        );
    }

    #[test]
    fn rejects_duplicate_symbol_assignment() {
        assert!(matches!(
            VersionScript::parse(
                b"VERS_1 { global: api; }; VERS_2 { global: api; };"
            ),
            Err(VersionScriptError::DuplicateSymbol { .. })
        ));
    }
}
