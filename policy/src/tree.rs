use serde::{Deserialize, Serialize};

/// A monotone access structure expressed as a threshold tree.
/// A leaf requires the decrypting party to hold the named attribute.
/// An internal node requires at least `threshold` of its `children`
/// to be satisfiable. AND is threshold == children.len(), OR is
/// threshold == 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessTree {
    Leaf(String),
    Gate {
        threshold: usize,
        children: Vec<AccessTree>,
    },
}

impl AccessTree {
    pub fn leaf(attribute: impl Into<String>) -> Self {
        AccessTree::Leaf(attribute.into())
    }

    pub fn and(children: Vec<AccessTree>) -> Self {
        let n = children.len();
        AccessTree::Gate {
            threshold: n,
            children,
        }
    }

    pub fn or(children: Vec<AccessTree>) -> Self {
        AccessTree::Gate {
            threshold: 1,
            children,
        }
    }

    pub fn threshold(k: usize, children: Vec<AccessTree>) -> Self {
        AccessTree::Gate {
            threshold: k,
            children,
        }
    }

    /// True if the given attribute set can satisfy this tree, ignoring
    /// cryptographic material. Used for pre-flight checks and tests.
    pub fn is_satisfied_by(&self, attrs: &[String]) -> bool {
        match self {
            AccessTree::Leaf(a) => attrs.iter().any(|x| x == a),
            AccessTree::Gate {
                threshold,
                children,
            } => {
                let satisfied = children
                    .iter()
                    .filter(|c| c.is_satisfied_by(attrs))
                    .count();
                satisfied >= *threshold
            }
        }
    }

    pub fn leaves(&self) -> Vec<&str> {
        match self {
            AccessTree::Leaf(a) => vec![a.as_str()],
            AccessTree::Gate { children, .. } => {
                children.iter().flat_map(|c| c.leaves()).collect()
            }
        }
    }
}
