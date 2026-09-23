use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionScript {
    assignments: BTreeMap<Vec<u8>, Vec<u8>>,
    prefix_patterns: BTreeMap<Vec<u8>, Vec<u8>>,
    versions: BTreeSet<Vec<u8>>,
    parents: BTreeMap<Vec<u8>, Vec<u8>>,
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
        let mut prefix_patterns = BTreeMap::new();
        let mut versions = BTreeSet::new();
        let mut parents = BTreeMap::new();
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
                            let symbol = cursor.expect_word("global symbol or prefix pattern")?;
                            if symbol
                                .iter()
                                .any(|byte| matches!(*byte, b'?' | b'[' | b']'))
                            {
                                return Err(VersionScriptError::UnsupportedGlobalPattern {
                                    prefix: symbol,
                                });
                            }
                            saw_symbol = true;
                            if cursor.peek_is(TokenKind::Star) {
                                cursor.advance();
                                if !cursor.peek_is(TokenKind::Semi) {
                                    return Err(VersionScriptError::UnsupportedGlobalPattern {
                                        prefix: symbol,
                                    });
                                }
                                cursor
                                    .expect(TokenKind::Semi, "';' after global prefix pattern")?;
                                if prefix_patterns
                                    .insert(symbol.clone(), version.clone())
                                    .is_some()
                                {
                                    return Err(VersionScriptError::DuplicatePattern {
                                        prefix: symbol,
                                    });
                                }
                            } else {
                                cursor.expect(TokenKind::Semi, "';' after global symbol")?;
                                if assignments
                                    .insert(symbol.clone(), version.clone())
                                    .is_some()
                                {
                                    return Err(VersionScriptError::DuplicateSymbol { symbol });
                                }
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
            if !cursor.peek_is(TokenKind::Semi) {
                let parent = cursor.expect_word("parent version name")?;
                parents.insert(version.clone(), parent);
            }
            cursor.expect(TokenKind::Semi, "';' after version block")?;
        }

        if assignments.is_empty() && prefix_patterns.is_empty() {
            return Err(VersionScriptError::NoGlobalSymbols);
        }

        for (version, parent) in &parents {
            if !versions.contains(parent) {
                return Err(VersionScriptError::UnknownParent {
                    version: version.clone(),
                    parent: parent.clone(),
                });
            }
        }
        for version in &versions {
            let mut seen = BTreeSet::new();
            let mut current = version.as_slice();
            while let Some(parent) = parents.get(current) {
                if !seen.insert(current.to_vec()) {
                    return Err(VersionScriptError::InheritanceCycle {
                        version: version.clone(),
                    });
                }
                current = parent;
            }
        }

        Ok(Self {
            assignments,
            prefix_patterns,
            versions,
            parents,
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

    pub fn resolve_version(&self, symbol: &[u8]) -> Result<Option<&[u8]>, VersionScriptMatchError> {
        if let Some(version) = self.assignments.get(symbol) {
            return Ok(Some(version.as_slice()));
        }

        let mut matched: Option<&Vec<u8>> = None;
        for (prefix, version) in &self.prefix_patterns {
            if !symbol.starts_with(prefix) {
                continue;
            }
            match matched {
                None => matched = Some(version),
                Some(existing) if existing == version => {}
                Some(existing) => {
                    return Err(VersionScriptMatchError::MultiplePrefixVersions {
                        symbol: symbol.to_vec(),
                        first_version: existing.clone(),
                        second_version: version.clone(),
                    });
                }
            }
        }
        Ok(matched.map(Vec::as_slice))
    }

    pub fn versions(&self) -> impl Iterator<Item = &[u8]> {
        self.versions.iter().map(Vec::as_slice)
    }

    pub fn parent_for(&self, version: &[u8]) -> Option<&[u8]> {
        self.parents.get(version).map(Vec::as_slice)
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
    UnsupportedGlobalPattern {
        prefix: Vec<u8>,
    },
    UnsupportedLocalPattern,
    UnknownParent {
        version: Vec<u8>,
        parent: Vec<u8>,
    },
    InheritanceCycle {
        version: Vec<u8>,
    },
    DuplicateVersion {
        version: Vec<u8>,
    },
    DuplicateSymbol {
        symbol: Vec<u8>,
    },
    DuplicatePattern {
        prefix: Vec<u8>,
    },
    NoGlobalSymbols,
}

impl fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainsNul => write!(f, "version script contains NUL"),
            Self::UnterminatedBlockComment => {
                write!(f, "version script has unterminated block comment")
            }
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
                "bounded version-script global patterns require a non-empty literal prefix before '*'"
            ),
            Self::UnsupportedGlobalPattern { prefix } => write!(
                f,
                "bounded version-script global pattern {:?} supports only one trailing '*'",
                String::from_utf8_lossy(prefix)
            ),
            Self::UnsupportedLocalPattern => write!(
                f,
                "bounded version scripts support only local: *;"
            ),
            Self::UnknownParent { version, parent } => write!(
                f,
                "version {:?} inherits from undefined parent version {:?}",
                String::from_utf8_lossy(version),
                String::from_utf8_lossy(parent)
            ),
            Self::InheritanceCycle { version } => write!(
                f,
                "version-definition inheritance contains a cycle reachable from {:?}",
                String::from_utf8_lossy(version)
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
            Self::DuplicatePattern { prefix } => write!(
                f,
                "version script assigns prefix pattern {:?}* more than once",
                String::from_utf8_lossy(prefix)
            ),
            Self::NoGlobalSymbols => write!(
                f,
                "version script must assign at least one exact global symbol or bounded prefix pattern"
            ),
        }
    }
}

impl std::error::Error for VersionScriptError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionScriptMatchError {
    MultiplePrefixVersions {
        symbol: Vec<u8>,
        first_version: Vec<u8>,
        second_version: Vec<u8>,
    },
}

impl fmt::Display for VersionScriptMatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiplePrefixVersions {
                symbol,
                first_version,
                second_version,
            } => write!(
                f,
                "symbol {:?} matches multiple bounded prefix patterns assigned to different versions {:?} and {:?}",
                String::from_utf8_lossy(symbol),
                String::from_utf8_lossy(first_version),
                String::from_utf8_lossy(second_version)
            ),
        }
    }
}

impl std::error::Error for VersionScriptMatchError {}

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
            while index < input.len() && input[index] != b'\n' {
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
    fn parses_single_parent_inheritance_and_rejects_global_wildcards() {
        let script =
            VersionScript::parse(b"VERS_1 { global: old_api; }; VERS_2 { global: api; } VERS_1;")
                .unwrap();
        assert_eq!(script.parent_for(b"VERS_1"), None);
        assert_eq!(script.parent_for(b"VERS_2"), Some(b"VERS_1".as_slice()));

        assert_eq!(
            VersionScript::parse(b"VERS_1 { global: *; };"),
            Err(VersionScriptError::UnsupportedGlobalWildcard)
        );
    }

    #[test]
    fn resolves_prefix_patterns_with_exact_precedence_and_detects_conflicts() {
        let script = VersionScript::parse(
            b"VERS_1 { global: api_special; api_*; }; VERS_2 { global: other_*; };",
        )
        .unwrap();
        assert_eq!(
            script.resolve_version(b"api_special").unwrap(),
            Some(b"VERS_1".as_slice())
        );
        assert_eq!(
            script.resolve_version(b"api_other").unwrap(),
            Some(b"VERS_1".as_slice())
        );
        assert_eq!(
            script.resolve_version(b"other_value").unwrap(),
            Some(b"VERS_2".as_slice())
        );
        assert_eq!(script.resolve_version(b"private").unwrap(), None);

        let conflicting =
            VersionScript::parse(b"VERS_A { global: api_*; }; VERS_B { global: api_v*; };")
                .unwrap();
        assert!(matches!(
            conflicting.resolve_version(b"api_v2"),
            Err(super::VersionScriptMatchError::MultiplePrefixVersions { .. })
        ));
    }

    #[test]
    fn rejects_nonprefix_global_patterns() {
        for input in [
            b"VERS_1 { global: api_*_suffix; };".as_slice(),
            b"VERS_1 { global: api_?; };".as_slice(),
            b"VERS_1 { global: api_[0-9]; };".as_slice(),
        ] {
            assert!(matches!(
                VersionScript::parse(input),
                Err(VersionScriptError::UnsupportedGlobalPattern { .. })
            ));
        }
        assert_eq!(
            VersionScript::parse(b"VERS_1 { global: *; };"),
            Err(VersionScriptError::UnsupportedGlobalWildcard)
        );
    }

    #[test]
    fn rejects_unknown_and_cyclic_inheritance() {
        assert!(matches!(
            VersionScript::parse(b"VERS_2 { global: api; } MISSING;"),
            Err(VersionScriptError::UnknownParent { .. })
        ));
        assert!(matches!(
            VersionScript::parse(
                b"VERS_1 { global: old_api; } VERS_2; VERS_2 { global: new_api; } VERS_1;"
            ),
            Err(VersionScriptError::InheritanceCycle { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_symbol_assignment() {
        assert!(matches!(
            VersionScript::parse(b"VERS_1 { global: api; }; VERS_2 { global: api; };"),
            Err(VersionScriptError::DuplicateSymbol { .. })
        ));
    }
}
