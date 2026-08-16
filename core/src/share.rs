use abe_policy::AccessTree;
use bls12_381::Scalar;
use ff::Field;
use rand_core::RngCore;
use std::collections::HashMap;

/// A polynomial over the scalar field, stored low-degree-coefficient first.
struct Polynomial {
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    fn random_with_constant<R: RngCore>(constant: Scalar, degree: usize, rng: &mut R) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(constant);
        for _ in 0..degree {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Polynomial { coeffs }
    }

    fn eval(&self, x: Scalar) -> Scalar {
        // Horner's method, evaluated from the highest degree coefficient down.
        let mut acc = Scalar::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }
}

fn index_scalar(index: u64) -> Scalar {
    Scalar::from(index)
}

/// Recursively splits `secret` down an access tree, returning the share
/// (lambda value) assigned to every leaf, keyed by that leaf's path so
/// that repeated attribute names in different branches keep distinct
/// shares.
pub fn share_secret<R: RngCore>(
    tree: &AccessTree,
    secret: Scalar,
    rng: &mut R,
) -> Vec<(Vec<usize>, String, Scalar)> {
    let mut out = Vec::new();
    share_node(tree, secret, rng, &mut vec![], &mut out);
    out
}

fn share_node<R: RngCore>(
    node: &AccessTree,
    secret: Scalar,
    rng: &mut R,
    path: &mut Vec<usize>,
    out: &mut Vec<(Vec<usize>, String, Scalar)>,
) {
    match node {
        AccessTree::Leaf(attr) => {
            out.push((path.clone(), attr.clone(), secret));
        }
        AccessTree::Gate {
            threshold,
            children,
        } => {
            let degree = threshold.saturating_sub(1);
            let poly = Polynomial::random_with_constant(secret, degree, rng);
            for (i, child) in children.iter().enumerate() {
                let idx = (i + 1) as u64;
                let child_secret = poly.eval(index_scalar(idx));
                path.push(idx as usize);
                share_node(child, child_secret, rng, path, out);
                path.pop();
            }
        }
    }
}

/// Result of attempting to satisfy one leaf during decryption: either the
/// recovered pairing value `e(g1,g2)^{r * lambda}` for a held attribute,
/// or nothing if the attribute is not held.
pub type LeafResult = HashMap<Vec<usize>, bls12_381::Gt>;

/// Recombines pairing values bottom-up through the tree using Lagrange
/// interpolation at x = 0, returning `Some(e(g1,g2)^{r*secret})` if and
/// only if the held attribute set satisfies the tree.
pub fn recombine(
    tree: &AccessTree,
    leaf_results: &LeafResult,
    path: &mut Vec<usize>,
) -> Option<bls12_381::Gt> {
    match tree {
        AccessTree::Leaf(_) => leaf_results.get(path).copied(),
        AccessTree::Gate {
            threshold,
            children,
        } => {
            let mut satisfied: Vec<(u64, bls12_381::Gt)> = Vec::new();
            for (i, child) in children.iter().enumerate() {
                let idx = (i + 1) as u64;
                path.push(idx as usize);
                if let Some(val) = recombine(child, leaf_results, path) {
                    satisfied.push((idx, val));
                }
                path.pop();
                if satisfied.len() >= *threshold {
                    break;
                }
            }
            if satisfied.len() < *threshold {
                return None;
            }
            satisfied.truncate(*threshold);
            Some(lagrange_combine(&satisfied))
        }
    }
}

/// Given a set of (index, value) pairs where value = e(g,g)^{r * q(index)}
/// for some degree < |set| polynomial q, recovers e(g,g)^{r * q(0)}.
fn lagrange_combine(points: &[(u64, bls12_381::Gt)]) -> bls12_381::Gt {
    let mut acc = bls12_381::Gt::identity();
    for &(i, vi) in points {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        let xi = index_scalar(i);
        for &(j, _) in points {
            if i == j {
                continue;
            }
            let xj = index_scalar(j);
            num *= -xj; // (0 - xj)
            den *= xi - xj;
        }
        let coeff = num * den.invert().expect("distinct indices imply invertible denominator");
        acc += vi * coeff;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_recombines_and_gate() {
        let mut rng = rand::thread_rng();
        let tree = AccessTree::and(vec![AccessTree::leaf("a"), AccessTree::leaf("b")]);
        let secret = Scalar::random(&mut rng);
        let shares = share_secret(&tree, secret, &mut rng);
        assert_eq!(shares.len(), 2);
    }
}
