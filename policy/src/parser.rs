use crate::tree::AccessTree;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("unexpected end of policy expression")]
    UnexpectedEof,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("empty attribute literal")]
    EmptyAttribute,
    #[error("unbalanced parentheses")]
    Unbalanced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Attr(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>, PolicyError> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    let flush = |current: &mut String, tokens: &mut Vec<Token>| -> Result<(), PolicyError> {
        if current.is_empty() {
            return Ok(());
        }
        let word = std::mem::take(current);
        match word.to_ascii_uppercase().as_str() {
            "AND" => tokens.push(Token::And),
            "OR" => tokens.push(Token::Or),
            _ => tokens.push(Token::Attr(word)),
        }
        Ok(())
    };

    for ch in input.chars() {
        match ch {
            '(' => {
                flush(&mut current, &mut tokens)?;
                tokens.push(Token::LParen);
            }
            ')' => {
                flush(&mut current, &mut tokens)?;
                tokens.push(Token::RParen);
            }
            c if c.is_whitespace() => {
                flush(&mut current, &mut tokens)?;
            }
            c => current.push(c),
        }
    }
    flush(&mut current, &mut tokens)?;
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    // policy := orExpr
    fn parse_policy(&mut self) -> Result<AccessTree, PolicyError> {
        let tree = self.parse_or()?;
        if self.pos != self.tokens.len() {
            return Err(PolicyError::UnexpectedToken(format!("{:?}", self.peek())));
        }
        Ok(tree)
    }

    // orExpr := andExpr (OR andExpr)*
    fn parse_or(&mut self) -> Result<AccessTree, PolicyError> {
        let mut children = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Token::Or)) {
            self.next();
            children.push(self.parse_and()?);
        }
        if children.len() == 1 {
            Ok(children.pop().unwrap())
        } else {
            Ok(AccessTree::or(children))
        }
    }

    // andExpr := atom (AND atom)*
    fn parse_and(&mut self) -> Result<AccessTree, PolicyError> {
        let mut children = vec![self.parse_atom()?];
        while matches!(self.peek(), Some(Token::And)) {
            self.next();
            children.push(self.parse_atom()?);
        }
        if children.len() == 1 {
            Ok(children.pop().unwrap())
        } else {
            Ok(AccessTree::and(children))
        }
    }

    // atom := '(' orExpr ')' | attribute
    fn parse_atom(&mut self) -> Result<AccessTree, PolicyError> {
        match self.next() {
            Some(Token::LParen) => {
                let inner = self.parse_or()?;
                match self.next() {
                    Some(Token::RParen) => Ok(inner),
                    _ => Err(PolicyError::Unbalanced),
                }
            }
            Some(Token::Attr(a)) => {
                if a.is_empty() {
                    Err(PolicyError::EmptyAttribute)
                } else {
                    Ok(AccessTree::leaf(normalize(&a)))
                }
            }
            Some(other) => Err(PolicyError::UnexpectedToken(format!("{:?}", other))),
            None => Err(PolicyError::UnexpectedEof),
        }
    }
}

/// Canonicalizes an attribute literal so that policy strings and
/// authority-issued attribute strings compare equal regardless of
/// incidental whitespace or quoting.
fn normalize(raw: &str) -> String {
    raw.replace('"', "").replace(' ', "").trim().to_string()
}

/// Parses a policy expression such as:
///   (department=security AND clearance>=4) OR role=admin
pub fn parse(input: &str) -> Result<AccessTree, PolicyError> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(PolicyError::UnexpectedEof);
    }
    let mut parser = Parser { tokens, pos: 0 };
    parser.parse_policy()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and() {
        let tree = parse("department=security AND clearance>=4").unwrap();
        assert!(tree.is_satisfied_by(&[
            "department=security".into(),
            "clearance>=4".into()
        ]));
        assert!(!tree.is_satisfied_by(&["department=security".into()]));
    }

    #[test]
    fn parses_or_with_parens() {
        let tree = parse("(department=security AND clearance>=4) OR role=admin").unwrap();
        assert!(tree.is_satisfied_by(&["role=admin".into()]));
        assert!(!tree.is_satisfied_by(&["department=marketing".into()]));
    }

    #[test]
    fn rejects_unbalanced() {
        assert!(parse("(department=security AND clearance>=4").is_err());
    }
}
