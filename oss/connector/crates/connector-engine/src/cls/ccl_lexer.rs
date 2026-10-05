//! CCL Lexer — tokenizes CCL native syntax and YAML contract sources.
//!
//! Implements the tokenizer specified in CONNECTOR_CONTRACT_LANGUAGE.md §8.
//! Features:
//!   - 62 reserved keywords with O(1) lookup via HashMap
//!   - String, Ident, Number, VarRef, Comment modes
//!   - Error recovery: unterminated strings, illegal chars, malformed varrefs
//!   - Source positions: line, column, byte offset per token
//!   - Multi-line comment support (/* ... */)

use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Source Span
// ═══════════════════════════════════════════════════════════════

/// A position in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
    pub offset: u32,
}

/// A span in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: Pos,
    pub end: Pos,
}

impl Span {
    pub fn new(start: Pos, end: Pos) -> Self {
        Self { start, end }
    }
    pub fn point(pos: Pos) -> Self {
        Self { start: pos, end: pos }
    }
}

// ═══════════════════════════════════════════════════════════════
// Token Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // ── Structural ──
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Colon,
    Dot,
    Newline,
    Semicolon,

    // ── Operators ──
    Arrow,      // ->
    FatArrow,   // =>
    Assign,     // =
    Gt,         // >
    Lt,         // <
    Gte,        // >=
    Lte,        // <=
    Eq,         // ==
    Neq,        // !=
    Pipe,       // |>
    Plus,       // +
    Minus,      // -
    Star,       // *
    Slash,      // /
    Percent,    // %
    Question,   // ? (optional type modifier)

    // ── Contract keywords ──
    KwContract,
    KwSolution,      // NEW: solution block (constitutional)
    KwIdentity,
    KwInterface,
    KwState,
    KwGovernance,
    KwBudget,
    KwMemory,
    KwBehavior,
    KwImport,        // NEW: imports block
    KwCapabilities,  // NEW: capabilities block (constitutional)
    KwPolicy,        // NEW: policy block (constitutional)
    KwFlow,          // NEW: flow block with stages
    KwStage,         // NEW: stage within flow
    KwEvidence,      // NEW: evidence block (constitutional)
    KwOutcomes,      // NEW: outcomes block (constitutional)
    KwReview,        // NEW: review block (constitutional)

    // ── Interface keywords ──
    KwInput,
    KwOutput,
    KwEvent,
    KwTool,
    KwCapability,

    // ── State keywords ──
    KwInitial,
    KwTerminal,
    KwOn,
    KwWhen,

    // ── Governance keywords ──
    KwRequire,
    KwEnsure,
    KwInvariant,
    KwRoles,
    KwClearance,
    KwCompliance,
    KwOnFailure,
    KwDeny,          // NEW: policy deny rule
    KwAllow,         // NEW: policy allow rule
    KwRecord,        // NEW: evidence record
    KwVerify,        // NEW: evidence verify
    KwRoute,         // NEW: flow route
    KwFail,          // NEW: flow fail

    // ── Behavior keywords ──
    KwStep,
    KwInfer,
    KwRecall,
    KwRemember,
    KwSet,
    KwBranch,
    KwTransition,
    KwEmit,
    KwCheckpoint,
    KwCall,
    KwSend,
    KwWait,
    KwParallel,
    KwSaga,

    // ── Type keywords ──
    KwString,
    KwInt,
    KwFloat,
    KwBool,
    KwJson,
    KwBinary,
    KwCid,
    KwList,
    KwMap,

    // ── Modifier keywords ──
    KwRequired,
    KwOptional,
    KwAs,
    KwWith,
    KwOtherwise,
    KwUse,
    KwAnd,
    KwOr,
    KwNot,
    KwIs,
    KwPresent,
    KwIn,
    KwMatches,
    KwHas,
    KwRole,
    KwAgent,
    // ── Constitutional modifiers ──
    KwDomain,        // NEW: solution domain
    KwOwner,         // NEW: solution owner
    KwVersion,       // NEW: solution version
    KwSchema,        // NEW: import schema
    KwPolicyPack,    // NEW: import policy_pack
    KwToolContract,  // NEW: import tool_contract
    KwAdvisory,      // NEW: capability advisory
    KwBinding,       // NEW: capability binding
    KwReadonly,      // NEW: memory readonly
    KwReadwrite,     // NEW: memory readwrite
    KwProtocol,      // NEW: capability protocol
    KwModel,         // NEW: capability model
    KwReviewQueue,   // NEW: capability review_queue
    KwTrust,         // NEW: input trust level
    KwVerified,      // NEW: trust verified
    KwUntrusted,     // NEW: trust untrusted
    KwQueue,         // NEW: review queue
    KwOnTimeout,     // NEW: review on_timeout
    KwOutside,       // NEW: policy outside
    KwUnless,        // NEW: policy unless
    KwConforms,      // NEW: policy conforms
    KwAny,           // NEW: state any
    // ── Extended types ──
    KwText,          // NEW: text type
    KwEnum,          // NEW: enum type
    KwDate,          // NEW: date type
    KwTime,          // NEW: time type
    KwDateTime,      // NEW: datetime type
    KwDocument,      // NEW: document type
    KwReference,     // NEW: reference type
    KwToolResult,    // NEW: tool_result<T>
    KwEvidenceRef,   // NEW: evidence_ref
    KwPolicyResult,  // NEW: policy_result
    KwTrusted,       // NEW: trusted<T>
    KwPii,           // NEW: pii<T>
    // ── Validation constraints ──
    KwRange,         // NEW: range constraint
    KwMinItems,      // NEW: min_items constraint
    KwMaxItems,      // NEW: max_items constraint
    KwMinLength,     // NEW: min_length constraint
    KwMaxLength,     // NEW: max_length constraint
    KwPattern,       // NEW: pattern constraint
    KwOneOf,         // NEW: one_of constraint
    // ── Range operator ──
    DotDot,          // .. for ranges

    // ── Literals ──
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolTrue,
    BoolFalse,
    NullLit,

    // ── Identifiers ──
    Ident(String),

    // ── References ──
    VarRef(String), // ${ident.path}

    // ── Comments ──
    Comment(String),

    // ── Special ──
    Eof,
    Error(LexError),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub lexeme: String,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span, lexeme: impl Into<String>) -> Self {
        Self { kind, span, lexeme: lexeme.into() }
    }

    pub fn is_keyword(&self) -> bool {
        matches!(
            self.kind,
            TokenKind::KwContract | TokenKind::KwIdentity | TokenKind::KwInterface |
            TokenKind::KwState | TokenKind::KwGovernance | TokenKind::KwBudget |
            TokenKind::KwMemory | TokenKind::KwBehavior | TokenKind::KwInput |
            TokenKind::KwOutput | TokenKind::KwEvent | TokenKind::KwTool |
            TokenKind::KwCapability | TokenKind::KwInitial | TokenKind::KwTerminal |
            TokenKind::KwOn | TokenKind::KwWhen | TokenKind::KwRequire |
            TokenKind::KwEnsure | TokenKind::KwInvariant | TokenKind::KwRoles |
            TokenKind::KwClearance | TokenKind::KwCompliance | TokenKind::KwOnFailure |
            TokenKind::KwStep | TokenKind::KwInfer | TokenKind::KwRecall |
            TokenKind::KwRemember | TokenKind::KwSet | TokenKind::KwBranch |
            TokenKind::KwTransition | TokenKind::KwEmit | TokenKind::KwCheckpoint |
            TokenKind::KwCall | TokenKind::KwSend | TokenKind::KwWait |
            TokenKind::KwParallel | TokenKind::KwSaga | TokenKind::KwString |
            TokenKind::KwInt | TokenKind::KwFloat | TokenKind::KwBool |
            TokenKind::KwJson | TokenKind::KwBinary | TokenKind::KwCid |
            TokenKind::KwList | TokenKind::KwMap | TokenKind::KwRequired |
            TokenKind::KwOptional | TokenKind::KwAs | TokenKind::KwWith |
            TokenKind::KwOtherwise | TokenKind::KwUse | TokenKind::KwAnd |
            TokenKind::KwOr | TokenKind::KwNot | TokenKind::KwIs |
            TokenKind::KwPresent | TokenKind::KwIn | TokenKind::KwMatches |
            TokenKind::KwHas | TokenKind::KwRole | TokenKind::KwAgent |
            TokenKind::BoolTrue | TokenKind::BoolFalse | TokenKind::NullLit
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(self.kind, TokenKind::Error(_))
    }

    pub fn is_eof(&self) -> bool {
        matches!(self.kind, TokenKind::Eof)
    }
}

// ═══════════════════════════════════════════════════════════════
// Keyword table (62 reserved words)
// ═══════════════════════════════════════════════════════════════

fn build_keyword_table() -> HashMap<&'static str, TokenKind> {
    let mut m = HashMap::with_capacity(100);
    // Contract blocks
    m.insert("contract", TokenKind::KwContract);
    m.insert("solution", TokenKind::KwSolution);
    m.insert("identity", TokenKind::KwIdentity);
    m.insert("interface", TokenKind::KwInterface);
    m.insert("state", TokenKind::KwState);
    m.insert("governance", TokenKind::KwGovernance);
    m.insert("budget", TokenKind::KwBudget);
    m.insert("memory", TokenKind::KwMemory);
    m.insert("behavior", TokenKind::KwBehavior);
    // Constitutional blocks
    m.insert("import", TokenKind::KwImport);
    m.insert("capabilities", TokenKind::KwCapabilities);
    m.insert("policy", TokenKind::KwPolicy);
    m.insert("flow", TokenKind::KwFlow);
    m.insert("stage", TokenKind::KwStage);
    m.insert("evidence", TokenKind::KwEvidence);
    m.insert("outcomes", TokenKind::KwOutcomes);
    m.insert("review", TokenKind::KwReview);
    // Interface
    m.insert("input", TokenKind::KwInput);
    m.insert("output", TokenKind::KwOutput);
    m.insert("event", TokenKind::KwEvent);
    m.insert("tool", TokenKind::KwTool);
    m.insert("capability", TokenKind::KwCapability);
    // State
    m.insert("initial", TokenKind::KwInitial);
    m.insert("terminal", TokenKind::KwTerminal);
    m.insert("on", TokenKind::KwOn);
    m.insert("when", TokenKind::KwWhen);
    m.insert("any", TokenKind::KwAny);
    // Governance / Policy
    m.insert("require", TokenKind::KwRequire);
    m.insert("ensure", TokenKind::KwEnsure);
    m.insert("invariant", TokenKind::KwInvariant);
    m.insert("roles", TokenKind::KwRoles);
    m.insert("clearance", TokenKind::KwClearance);
    m.insert("compliance", TokenKind::KwCompliance);
    m.insert("on_failure", TokenKind::KwOnFailure);
    m.insert("deny", TokenKind::KwDeny);
    m.insert("allow", TokenKind::KwAllow);
    m.insert("record", TokenKind::KwRecord);
    m.insert("verify", TokenKind::KwVerify);
    m.insert("route", TokenKind::KwRoute);
    m.insert("fail", TokenKind::KwFail);
    // Behavior
    m.insert("step", TokenKind::KwStep);
    m.insert("infer", TokenKind::KwInfer);
    m.insert("recall", TokenKind::KwRecall);
    m.insert("remember", TokenKind::KwRemember);
    m.insert("set", TokenKind::KwSet);
    m.insert("branch", TokenKind::KwBranch);
    m.insert("transition", TokenKind::KwTransition);
    m.insert("emit", TokenKind::KwEmit);
    m.insert("checkpoint", TokenKind::KwCheckpoint);
    m.insert("call", TokenKind::KwCall);
    m.insert("send", TokenKind::KwSend);
    m.insert("wait", TokenKind::KwWait);
    m.insert("parallel", TokenKind::KwParallel);
    m.insert("saga", TokenKind::KwSaga);
    // Types (both capitalized and lowercase)
    m.insert("String", TokenKind::KwString);
    m.insert("string", TokenKind::KwString);
    m.insert("Int", TokenKind::KwInt);
    m.insert("int", TokenKind::KwInt);
    m.insert("Float", TokenKind::KwFloat);
    m.insert("float", TokenKind::KwFloat);
    m.insert("Bool", TokenKind::KwBool);
    m.insert("bool", TokenKind::KwBool);
    m.insert("Json", TokenKind::KwJson);
    m.insert("json", TokenKind::KwJson);
    m.insert("Binary", TokenKind::KwBinary);
    m.insert("binary", TokenKind::KwBinary);
    m.insert("Cid", TokenKind::KwCid);
    m.insert("cid", TokenKind::KwCid);
    m.insert("List", TokenKind::KwList);
    m.insert("Map", TokenKind::KwMap);
    // Modifiers
    m.insert("required", TokenKind::KwRequired);
    m.insert("optional", TokenKind::KwOptional);
    m.insert("as", TokenKind::KwAs);
    m.insert("with", TokenKind::KwWith);
    m.insert("otherwise", TokenKind::KwOtherwise);
    m.insert("use", TokenKind::KwUse);
    m.insert("and", TokenKind::KwAnd);
    m.insert("or", TokenKind::KwOr);
    m.insert("not", TokenKind::KwNot);
    m.insert("is", TokenKind::KwIs);
    m.insert("present", TokenKind::KwPresent);
    m.insert("in", TokenKind::KwIn);
    m.insert("matches", TokenKind::KwMatches);
    m.insert("has", TokenKind::KwHas);
    m.insert("role", TokenKind::KwRole);
    m.insert("agent", TokenKind::KwAgent);
    // Constitutional modifiers
    m.insert("domain", TokenKind::KwDomain);
    m.insert("owner", TokenKind::KwOwner);
    m.insert("version", TokenKind::KwVersion);
    m.insert("schema", TokenKind::KwSchema);
    m.insert("policy_pack", TokenKind::KwPolicyPack);
    m.insert("tool_contract", TokenKind::KwToolContract);
    m.insert("advisory", TokenKind::KwAdvisory);
    m.insert("binding", TokenKind::KwBinding);
    m.insert("readonly", TokenKind::KwReadonly);
    m.insert("readwrite", TokenKind::KwReadwrite);
    m.insert("protocol", TokenKind::KwProtocol);
    m.insert("model", TokenKind::KwModel);
    m.insert("review_queue", TokenKind::KwReviewQueue);
    m.insert("trust", TokenKind::KwTrust);
    m.insert("verified", TokenKind::KwVerified);
    m.insert("untrusted", TokenKind::KwUntrusted);
    m.insert("queue", TokenKind::KwQueue);
    m.insert("on_timeout", TokenKind::KwOnTimeout);
    m.insert("outside", TokenKind::KwOutside);
    m.insert("unless", TokenKind::KwUnless);
    m.insert("conforms", TokenKind::KwConforms);
    // Extended types
    m.insert("text", TokenKind::KwText);
    m.insert("enum", TokenKind::KwEnum);
    m.insert("date", TokenKind::KwDate);
    m.insert("time", TokenKind::KwTime);
    m.insert("datetime", TokenKind::KwDateTime);
    m.insert("document", TokenKind::KwDocument);
    m.insert("reference", TokenKind::KwReference);
    m.insert("tool_result", TokenKind::KwToolResult);
    m.insert("evidence_ref", TokenKind::KwEvidenceRef);
    m.insert("policy_result", TokenKind::KwPolicyResult);
    m.insert("trusted", TokenKind::KwTrusted);
    m.insert("pii", TokenKind::KwPii);
    // Validation constraints
    m.insert("range", TokenKind::KwRange);
    m.insert("min_items", TokenKind::KwMinItems);
    m.insert("max_items", TokenKind::KwMaxItems);
    m.insert("min_length", TokenKind::KwMinLength);
    m.insert("max_length", TokenKind::KwMaxLength);
    m.insert("pattern", TokenKind::KwPattern);
    m.insert("one_of", TokenKind::KwOneOf);
    // Literal keywords
    m.insert("true", TokenKind::BoolTrue);
    m.insert("false", TokenKind::BoolFalse);
    m.insert("null", TokenKind::NullLit);
    m
}

// ═══════════════════════════════════════════════════════════════
// Lexer
// ═══════════════════════════════════════════════════════════════

pub struct CclLexer<'src> {
    source: &'src [u8],
    pos: usize,
    line: u32,
    col: u32,
    keywords: HashMap<&'static str, TokenKind>,
    errors: Vec<LexError>,
}

impl<'src> CclLexer<'src> {
    pub fn new(source: &'src str) -> Self {
        Self {
            source: source.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
            keywords: build_keyword_table(),
            errors: Vec::new(),
        }
    }

    /// Tokenize the entire source, including Eof.
    pub fn tokenize(source: &str) -> Vec<Token> {
        let mut lexer = CclLexer::new(source);
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token();
            let is_eof = tok.is_eof();
            tokens.push(tok);
            if is_eof { break; }
        }
        tokens
    }

    /// Tokenize, filtering out comments and newlines.
    pub fn tokenize_filtered(source: &str) -> Vec<Token> {
        Self::tokenize(source)
            .into_iter()
            .filter(|t| !matches!(t.kind, TokenKind::Comment(_) | TokenKind::Newline))
            .collect()
    }

    /// Get accumulated errors.
    pub fn errors(&self) -> &[LexError] {
        &self.errors
    }

    // ── Cursor helpers ──────────────────────────────────────────

    fn current_pos(&self) -> Pos {
        Pos { line: self.line, col: self.col, offset: self.pos as u32 }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    fn peek_ahead(&self, n: usize) -> Option<u8> {
        self.source.get(self.pos + n).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.source.get(self.pos).copied()?;
        self.pos += 1;
        if ch == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn slice(&self, start: usize, end: usize) -> &str {
        std::str::from_utf8(&self.source[start..end]).unwrap_or("")
    }

    fn skip_whitespace_no_newline(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == b' ' || ch == b'\t' || ch == b'\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    // ── Main dispatch ───────────────────────────────────────────

    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace_no_newline();

        if self.at_end() {
            return Token::new(TokenKind::Eof, Span::point(self.current_pos()), "");
        }

        let start = self.current_pos();
        let ch = self.peek().unwrap();

        match ch {
            b'\n' => {
                self.advance();
                Token::new(TokenKind::Newline, Span::new(start, self.current_pos()), "\n")
            }

            // String literal
            b'"' => self.lex_string(start),

            // VarRef ${...}
            b'$' if self.peek_ahead(1) == Some(b'{') => self.lex_varref(start),

            // Number
            b'0'..=b'9' => self.lex_number(start),

            // Identifier / keyword
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.lex_ident(start),

            // Structural
            b'{' => { self.advance(); Token::new(TokenKind::LBrace, Span::new(start, self.current_pos()), "{") }
            b'}' => { self.advance(); Token::new(TokenKind::RBrace, Span::new(start, self.current_pos()), "}") }
            b'[' => { self.advance(); Token::new(TokenKind::LBracket, Span::new(start, self.current_pos()), "[") }
            b']' => { self.advance(); Token::new(TokenKind::RBracket, Span::new(start, self.current_pos()), "]") }
            b'(' => { self.advance(); Token::new(TokenKind::LParen, Span::new(start, self.current_pos()), "(") }
            b')' => { self.advance(); Token::new(TokenKind::RParen, Span::new(start, self.current_pos()), ")") }
            b',' => { self.advance(); Token::new(TokenKind::Comma, Span::new(start, self.current_pos()), ",") }
            b':' => { self.advance(); Token::new(TokenKind::Colon, Span::new(start, self.current_pos()), ":") }
            b';' => { self.advance(); Token::new(TokenKind::Semicolon, Span::new(start, self.current_pos()), ";") }
            b'.' => {
                self.advance();
                if self.peek() == Some(b'.') {
                    self.advance();
                    Token::new(TokenKind::DotDot, Span::new(start, self.current_pos()), "..")
                } else {
                    Token::new(TokenKind::Dot, Span::new(start, self.current_pos()), ".")
                }
            }
            b'+' => { self.advance(); Token::new(TokenKind::Plus, Span::new(start, self.current_pos()), "+") }
            b'*' => { self.advance(); Token::new(TokenKind::Star, Span::new(start, self.current_pos()), "*") }
            b'%' => { self.advance(); Token::new(TokenKind::Percent, Span::new(start, self.current_pos()), "%") }

            // Operators with lookahead
            b'-' => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    Token::new(TokenKind::Arrow, Span::new(start, self.current_pos()), "->")
                } else {
                    Token::new(TokenKind::Minus, Span::new(start, self.current_pos()), "-")
                }
            }
            b'=' => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    Token::new(TokenKind::FatArrow, Span::new(start, self.current_pos()), "=>")
                } else if self.peek() == Some(b'=') {
                    self.advance();
                    Token::new(TokenKind::Eq, Span::new(start, self.current_pos()), "==")
                } else {
                    Token::new(TokenKind::Assign, Span::new(start, self.current_pos()), "=")
                }
            }
            b'>' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Token::new(TokenKind::Gte, Span::new(start, self.current_pos()), ">=")
                } else {
                    Token::new(TokenKind::Gt, Span::new(start, self.current_pos()), ">")
                }
            }
            b'<' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Token::new(TokenKind::Lte, Span::new(start, self.current_pos()), "<=")
                } else {
                    Token::new(TokenKind::Lt, Span::new(start, self.current_pos()), "<")
                }
            }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Token::new(TokenKind::Neq, Span::new(start, self.current_pos()), "!=")
                } else {
                    // standalone ! is an error
                    let err = LexError { code: "E_ILLEGAL_CHAR", message: "unexpected '!'".into() };
                    self.errors.push(err.clone());
                    Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), "!")
                }
            }
            b'|' => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    Token::new(TokenKind::Pipe, Span::new(start, self.current_pos()), "|>")
                } else {
                    let err = LexError { code: "E_ILLEGAL_CHAR", message: "unexpected '|', did you mean '|>'?".into() };
                    self.errors.push(err.clone());
                    Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), "|")
                }
            }

            // Question mark (optional type modifier)
            b'?' => { self.advance(); Token::new(TokenKind::Question, Span::new(start, self.current_pos()), "?") }

            // Comments or slash
            b'/' => {
                if self.peek_ahead(1) == Some(b'/') {
                    self.lex_line_comment(start)
                } else if self.peek_ahead(1) == Some(b'*') {
                    self.lex_block_comment(start)
                } else {
                    self.advance();
                    Token::new(TokenKind::Slash, Span::new(start, self.current_pos()), "/")
                }
            }

            // Negative number: only if '-' followed by digit and prev token would allow
            // (handled above in '-' branch as Minus; parser distinguishes unary)

            _ => {
                self.advance();
                let lexeme = String::from_utf8_lossy(&[ch]).to_string();
                let err = LexError {
                    code: "E_ILLEGAL_CHAR",
                    message: format!("illegal character '{}'", lexeme),
                };
                self.errors.push(err.clone());
                Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), lexeme)
            }
        }
    }

    // ── String mode ─────────────────────────────────────────────

    fn lex_string(&mut self, start: Pos) -> Token {
        self.advance(); // consume opening "
        let str_start = self.pos;
        let mut buf = String::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => {
                    // Unterminated string — error recovery: emit error, advance to newline
                    let err = LexError {
                        code: "E_UNTERM_STRING",
                        message: "unterminated string literal".into(),
                    };
                    self.errors.push(err.clone());
                    return Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), buf);
                }
                Some(b'"') => {
                    self.advance(); // consume closing "
                    return Token::new(
                        TokenKind::StringLit(buf.clone()),
                        Span::new(start, self.current_pos()),
                        format!("\"{}\"", buf),
                    );
                }
                Some(b'\\') => {
                    self.advance(); // consume backslash
                    match self.peek() {
                        Some(b'n') => { self.advance(); buf.push('\n'); }
                        Some(b't') => { self.advance(); buf.push('\t'); }
                        Some(b'\\') => { self.advance(); buf.push('\\'); }
                        Some(b'"') => { self.advance(); buf.push('"'); }
                        Some(b'r') => { self.advance(); buf.push('\r'); }
                        Some(b'0') => { self.advance(); buf.push('\0'); }
                        Some(c) => {
                            self.advance();
                            buf.push('\\');
                            buf.push(c as char);
                        }
                        None => {
                            let err = LexError {
                                code: "E_UNTERM_STRING",
                                message: "unterminated string literal after escape".into(),
                            };
                            self.errors.push(err.clone());
                            return Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), buf);
                        }
                    }
                }
                Some(c) => {
                    self.advance();
                    buf.push(c as char);
                }
            }
        }
    }

    // ── VarRef mode ─────────────────────────────────────────────

    fn lex_varref(&mut self, start: Pos) -> Token {
        self.advance(); // consume $
        self.advance(); // consume {
        let ref_start = self.pos;
        let mut depth = 0u32;

        // Scan up to 128 chars for closing }
        for _ in 0..128 {
            match self.peek() {
                Some(b'}') => {
                    let path = self.slice(ref_start, self.pos).to_string();
                    self.advance(); // consume }
                    return Token::new(
                        TokenKind::VarRef(path.clone()),
                        Span::new(start, self.current_pos()),
                        format!("${{{}}}", path),
                    );
                }
                Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' => {
                    self.advance();
                }
                None | Some(b'\n') => break,
                Some(_) => break,
            }
        }

        // Malformed varref
        let partial = self.slice(ref_start, self.pos).to_string();
        let err = LexError {
            code: "E_BAD_VARREF",
            message: format!("malformed variable reference '${{{}'", partial),
        };
        self.errors.push(err.clone());
        Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), format!("${{{}", partial))
    }

    // ── Number mode ─────────────────────────────────────────────

    fn lex_number(&mut self, start: Pos) -> Token {
        let num_start = self.pos;
        let mut is_float = false;

        // Integer part
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }

        // Decimal part
        if self.peek() == Some(b'.') {
            if let Some(next) = self.peek_ahead(1) {
                if next.is_ascii_digit() {
                    is_float = true;
                    self.advance(); // consume .
                    while let Some(ch) = self.peek() {
                        if ch.is_ascii_digit() {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        // Scientific notation (e.g., 1e10, 3.14e-2)
        if let Some(ch) = self.peek() {
            if ch == b'e' || ch == b'E' {
                is_float = true;
                self.advance();
                if let Some(sign) = self.peek() {
                    if sign == b'+' || sign == b'-' {
                        self.advance();
                    }
                }
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
            }
        }

        // Reject trailing alpha (e.g., 123abc)
        if let Some(ch) = self.peek() {
            if ch.is_ascii_alphabetic() || ch == b'_' {
                let bad_start = self.pos;
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        self.advance();
                    } else {
                        break;
                    }
                }
                let lexeme = self.slice(num_start, self.pos).to_string();
                let err = LexError {
                    code: "E_BAD_NUMBER",
                    message: format!("invalid number literal '{}'", lexeme),
                };
                self.errors.push(err.clone());
                return Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), lexeme);
            }
        }

        let lexeme = self.slice(num_start, self.pos).to_string();
        if is_float {
            let val: f64 = lexeme.parse().unwrap_or(0.0);
            Token::new(TokenKind::FloatLit(val), Span::new(start, self.current_pos()), lexeme)
        } else {
            let val: i64 = lexeme.parse().unwrap_or(0);
            Token::new(TokenKind::IntLit(val), Span::new(start, self.current_pos()), lexeme)
        }
    }

    // ── Identifier / keyword mode ───────────────────────────────

    fn lex_ident(&mut self, start: Pos) -> Token {
        let id_start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = self.slice(id_start, self.pos).to_string();

        // Check keyword table
        if let Some(kw) = self.keywords.get(lexeme.as_str()) {
            Token::new(kw.clone(), Span::new(start, self.current_pos()), lexeme)
        } else {
            Token::new(TokenKind::Ident(lexeme.clone()), Span::new(start, self.current_pos()), lexeme)
        }
    }

    // ── Comment modes ───────────────────────────────────────────

    fn lex_line_comment(&mut self, start: Pos) -> Token {
        self.advance(); // consume first /
        self.advance(); // consume second /
        let cmt_start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == b'\n' { break; }
            self.advance();
        }
        let text = self.slice(cmt_start, self.pos).trim().to_string();
        Token::new(TokenKind::Comment(text.clone()), Span::new(start, self.current_pos()), format!("//{}", text))
    }

    fn lex_block_comment(&mut self, start: Pos) -> Token {
        self.advance(); // consume /
        self.advance(); // consume *
        let cmt_start = self.pos;
        loop {
            match self.peek() {
                None => {
                    let text = self.slice(cmt_start, self.pos).to_string();
                    let err = LexError {
                        code: "E_UNTERM_COMMENT",
                        message: "unterminated block comment".into(),
                    };
                    self.errors.push(err.clone());
                    return Token::new(TokenKind::Error(err), Span::new(start, self.current_pos()), text);
                }
                Some(b'*') if self.peek_ahead(1) == Some(b'/') => {
                    let text = self.slice(cmt_start, self.pos).trim().to_string();
                    self.advance(); // consume *
                    self.advance(); // consume /
                    return Token::new(TokenKind::Comment(text.clone()), Span::new(start, self.current_pos()), format!("/*{}*/", text));
                }
                _ => { self.advance(); }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        CclLexer::tokenize(src).into_iter().map(|t| t.kind).collect()
    }

    fn kinds_filtered(src: &str) -> Vec<TokenKind> {
        CclLexer::tokenize_filtered(src).into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn test_empty() {
        assert_eq!(kinds(""), vec![TokenKind::Eof]);
    }

    #[test]
    fn test_structural_tokens() {
        let toks = kinds_filtered("{ } [ ] ( ) , : . ;");
        assert_eq!(toks, vec![
            TokenKind::LBrace, TokenKind::RBrace,
            TokenKind::LBracket, TokenKind::RBracket,
            TokenKind::LParen, TokenKind::RParen,
            TokenKind::Comma, TokenKind::Colon, TokenKind::Dot, TokenKind::Semicolon,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_operators() {
        let toks = kinds_filtered("-> => = > < >= <= == != |>");
        assert_eq!(toks, vec![
            TokenKind::Arrow, TokenKind::FatArrow, TokenKind::Assign,
            TokenKind::Gt, TokenKind::Lt, TokenKind::Gte, TokenKind::Lte,
            TokenKind::Eq, TokenKind::Neq, TokenKind::Pipe,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_arithmetic_operators() {
        let toks = kinds_filtered("+ - * / %");
        assert_eq!(toks, vec![
            TokenKind::Plus, TokenKind::Minus, TokenKind::Star, TokenKind::Slash, TokenKind::Percent,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_contract_keywords() {
        let toks = kinds_filtered("contract identity interface state governance budget memory behavior");
        assert_eq!(toks, vec![
            TokenKind::KwContract, TokenKind::KwIdentity, TokenKind::KwInterface,
            TokenKind::KwState, TokenKind::KwGovernance, TokenKind::KwBudget,
            TokenKind::KwMemory, TokenKind::KwBehavior,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_behavior_keywords() {
        let toks = kinds_filtered("step infer recall remember set branch transition emit checkpoint call send wait parallel saga");
        assert_eq!(toks, vec![
            TokenKind::KwStep, TokenKind::KwInfer, TokenKind::KwRecall,
            TokenKind::KwRemember, TokenKind::KwSet, TokenKind::KwBranch,
            TokenKind::KwTransition, TokenKind::KwEmit, TokenKind::KwCheckpoint,
            TokenKind::KwCall, TokenKind::KwSend, TokenKind::KwWait,
            TokenKind::KwParallel, TokenKind::KwSaga,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_type_keywords() {
        let toks = kinds_filtered("String Int Float Bool Json Binary Cid List Map");
        assert_eq!(toks, vec![
            TokenKind::KwString, TokenKind::KwInt, TokenKind::KwFloat,
            TokenKind::KwBool, TokenKind::KwJson, TokenKind::KwBinary,
            TokenKind::KwCid, TokenKind::KwList, TokenKind::KwMap,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_modifier_keywords() {
        let toks = kinds_filtered("required optional as with otherwise use and or not is present in matches has role agent");
        assert_eq!(toks, vec![
            TokenKind::KwRequired, TokenKind::KwOptional, TokenKind::KwAs,
            TokenKind::KwWith, TokenKind::KwOtherwise, TokenKind::KwUse,
            TokenKind::KwAnd, TokenKind::KwOr, TokenKind::KwNot,
            TokenKind::KwIs, TokenKind::KwPresent, TokenKind::KwIn,
            TokenKind::KwMatches, TokenKind::KwHas, TokenKind::KwRole,
            TokenKind::KwAgent,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn test_literals() {
        let toks = kinds_filtered("true false null");
        assert_eq!(toks, vec![TokenKind::BoolTrue, TokenKind::BoolFalse, TokenKind::NullLit, TokenKind::Eof]);
    }

    #[test]
    fn test_string_literal() {
        let toks = CclLexer::tokenize_filtered(r#""hello world""#);
        assert_eq!(toks[0].kind, TokenKind::StringLit("hello world".into()));
    }

    #[test]
    fn test_string_escapes() {
        let toks = CclLexer::tokenize_filtered(r#""line\nbreak\ttab\\slash\"quote""#);
        assert_eq!(toks[0].kind, TokenKind::StringLit("line\nbreak\ttab\\slash\"quote".into()));
    }

    #[test]
    fn test_integer_literal() {
        let toks = CclLexer::tokenize_filtered("42 0 99999");
        assert_eq!(toks[0].kind, TokenKind::IntLit(42));
        assert_eq!(toks[1].kind, TokenKind::IntLit(0));
        assert_eq!(toks[2].kind, TokenKind::IntLit(99999));
    }

    #[test]
    fn test_float_literal() {
        let toks = CclLexer::tokenize_filtered("3.14 0.5 1e10 2.5e-3");
        assert_eq!(toks[0].kind, TokenKind::FloatLit(3.14));
        assert_eq!(toks[1].kind, TokenKind::FloatLit(0.5));
        assert_eq!(toks[2].kind, TokenKind::FloatLit(1e10));
        assert_eq!(toks[3].kind, TokenKind::FloatLit(2.5e-3));
    }

    #[test]
    fn test_identifiers() {
        let toks = CclLexer::tokenize_filtered("my_agent patient_triage_v2 _private");
        assert_eq!(toks[0].kind, TokenKind::Ident("my_agent".into()));
        assert_eq!(toks[1].kind, TokenKind::Ident("patient_triage_v2".into()));
        assert_eq!(toks[2].kind, TokenKind::Ident("_private".into()));
    }

    #[test]
    fn test_varref() {
        let toks = CclLexer::tokenize_filtered("${patient_id} ${result.severity.score}");
        assert_eq!(toks[0].kind, TokenKind::VarRef("patient_id".into()));
        assert_eq!(toks[1].kind, TokenKind::VarRef("result.severity.score".into()));
    }

    #[test]
    fn test_line_comment() {
        let toks = CclLexer::tokenize("step // this is a comment\nrecall");
        let comment = toks.iter().find(|t| matches!(t.kind, TokenKind::Comment(_)));
        assert!(comment.is_some());
    }

    #[test]
    fn test_block_comment() {
        let toks = CclLexer::tokenize("step /* multi\nline\ncomment */ recall");
        let comment = toks.iter().find(|t| matches!(t.kind, TokenKind::Comment(_)));
        assert!(comment.is_some());
        let filtered = CclLexer::tokenize_filtered("step /* multi\nline */ recall");
        assert_eq!(filtered[0].kind, TokenKind::KwStep);
        assert_eq!(filtered[1].kind, TokenKind::KwRecall);
    }

    #[test]
    fn test_error_unterminated_string() {
        let toks = CclLexer::tokenize("\"hello\nworld");
        assert!(toks.iter().any(|t| t.is_error()));
    }

    #[test]
    fn test_error_illegal_char() {
        let toks = CclLexer::tokenize("step @ recall");
        assert!(toks.iter().any(|t| t.is_error()));
    }

    #[test]
    fn test_error_bad_number() {
        let toks = CclLexer::tokenize("123abc");
        assert!(toks.iter().any(|t| t.is_error()));
    }

    #[test]
    fn test_error_malformed_varref() {
        let toks = CclLexer::tokenize("${bad ref}");
        assert!(toks.iter().any(|t| t.is_error()));
    }

    #[test]
    fn test_error_recovery_continues() {
        // After an error, lexer should continue producing tokens
        let toks = CclLexer::tokenize_filtered("step @ recall");
        let non_err: Vec<_> = toks.iter().filter(|t| !t.is_error() && !t.is_eof()).collect();
        assert_eq!(non_err.len(), 2); // step + recall
    }

    #[test]
    fn test_span_positions() {
        let toks = CclLexer::tokenize("step");
        assert_eq!(toks[0].span.start.line, 1);
        assert_eq!(toks[0].span.start.col, 1);
        assert_eq!(toks[0].span.end.col, 5);
    }

    #[test]
    fn test_multiline_positions() {
        let toks = CclLexer::tokenize("step\nrecall");
        let recall = toks.iter().find(|t| t.kind == TokenKind::KwRecall).unwrap();
        assert_eq!(recall.span.start.line, 2);
        assert_eq!(recall.span.start.col, 1);
    }

    #[test]
    fn test_full_contract_snippet() {
        let src = r#"contract patient_triage {
  identity {
    name: "patient_triage"
    version: "1.0.0"
  }
  interface {
    input patient_id: String required
    output triage_result: Json
    tool lookup_patient
    event triage_complete
  }
  behavior {
    step intake {
      tool lookup_patient { id: ${patient_id} } -> patient
    }
    step assess {
      infer "assess severity" with ${patient} -> assessment
    }
    step route {
      branch {
        when ${assessment.severity} > 8.0 -> escalate
        otherwise -> complete
      }
    }
  }
}"#;
        let toks = CclLexer::tokenize_filtered(src);
        // Should have many tokens and no errors
        let errors: Vec<_> = toks.iter().filter(|t| t.is_error()).collect();
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);

        // Check key tokens are present
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwContract));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwIdentity));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwInterface));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwBehavior));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwStep));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwInfer));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwBranch));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwWhen));
        assert!(toks.iter().any(|t| t.kind == TokenKind::KwOtherwise));
        assert!(toks.iter().any(|t| matches!(t.kind, TokenKind::VarRef(_))));
        assert!(toks.iter().any(|t| matches!(t.kind, TokenKind::StringLit(_))));
        assert!(toks.iter().any(|t| matches!(t.kind, TokenKind::FloatLit(_))));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Arrow));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Gt));
    }

    #[test]
    fn test_keyword_count() {
        let table = build_keyword_table();
        // 122 previous + 7 lowercase type aliases = 129
        assert_eq!(table.len(), 129, "expected 129 reserved words, got {}", table.len());
    }
}
