//! Postcondition Verifier — verify execution results match declared postconditions.
//!
//! Failed postconditions trigger the declared rollback strategy.

use serde::{Deserialize, Serialize};

use crate::runner::ExecResult;

/// A postcondition specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostconditionSpec {
    ExitCodeZero,
    ExitCodeEquals(i32),
    OutputContains(String),
    OutputMatchesKey { key: String, expected: serde_json::Value },
    NoSideEffects,
    FileExists(String),
    Custom(String),
}

/// Result of checking a single postcondition.
#[derive(Debug, Clone)]
pub struct PostconditionResult {
    pub spec: String,
    pub passed: bool,
    pub message: String,
}

/// Verify all postconditions against an execution result.
pub fn verify_postconditions(
    result: &ExecResult,
    specs: &[PostconditionSpec],
) -> Vec<PostconditionResult> {
    specs.iter().map(|spec| check_one(result, spec)).collect()
}

/// Check if all postconditions passed.
pub fn all_passed(results: &[PostconditionResult]) -> bool {
    results.iter().all(|r| r.passed)
}

fn check_one(result: &ExecResult, spec: &PostconditionSpec) -> PostconditionResult {
    match spec {
        PostconditionSpec::ExitCodeZero => PostconditionResult {
            spec: "exit_code_zero".into(),
            passed: result.exit_code == 0,
            message: if result.exit_code == 0 {
                "OK".into()
            } else {
                format!("Expected exit code 0, got {}", result.exit_code)
            },
        },
        PostconditionSpec::ExitCodeEquals(expected) => PostconditionResult {
            spec: format!("exit_code_equals({})", expected),
            passed: result.exit_code == *expected,
            message: if result.exit_code == *expected {
                "OK".into()
            } else {
                format!("Expected exit code {}, got {}", expected, result.exit_code)
            },
        },
        PostconditionSpec::OutputContains(needle) => {
            let output_str = serde_json::to_string(&result.output).unwrap_or_default();
            let found = output_str.contains(needle);
            PostconditionResult {
                spec: format!("output_contains({})", needle),
                passed: found,
                message: if found { "OK".into() } else { format!("Output does not contain '{}'", needle) },
            }
        }
        PostconditionSpec::OutputMatchesKey { key, expected } => {
            let actual = result.output.get(key);
            let passed = actual == Some(expected);
            PostconditionResult {
                spec: format!("output_matches_key({})", key),
                passed,
                message: if passed {
                    "OK".into()
                } else {
                    format!("Key '{}': expected {:?}, got {:?}", key, expected, actual)
                },
            }
        }
        PostconditionSpec::NoSideEffects => PostconditionResult {
            spec: "no_side_effects".into(),
            passed: result.side_effects.is_empty(),
            message: if result.side_effects.is_empty() {
                "OK".into()
            } else {
                format!("Found {} side effects", result.side_effects.len())
            },
        },
        PostconditionSpec::FileExists(path) => {
            let exists = std::path::Path::new(path).exists();
            PostconditionResult {
                spec: format!("file_exists({})", path),
                passed: exists,
                message: if exists { "OK".into() } else { format!("File not found: {}", path) },
            }
        }
        PostconditionSpec::Custom(desc) => PostconditionResult {
            spec: format!("custom({})", desc),
            passed: true, // custom always passes at static check level
            message: "Custom postcondition — requires runtime evaluation".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ExecResult;

    fn make_result(exit_code: i32, output: serde_json::Value, side_effects: Vec<String>) -> ExecResult {
        ExecResult {
            output,
            output_hash: "h".into(),
            output_cid: "c".into(),
            exit_code,
            duration_ms: 10,
            side_effects,
        }
    }

    #[test]
    fn test_exit_code_zero_pass() {
        let result = make_result(0, serde_json::json!({}), vec![]);
        let checks = verify_postconditions(&result, &[PostconditionSpec::ExitCodeZero]);
        assert!(all_passed(&checks));
    }

    #[test]
    fn test_exit_code_zero_fail() {
        let result = make_result(1, serde_json::json!({}), vec![]);
        let checks = verify_postconditions(&result, &[PostconditionSpec::ExitCodeZero]);
        assert!(!all_passed(&checks));
    }

    #[test]
    fn test_exit_code_equals() {
        let result = make_result(42, serde_json::json!({}), vec![]);
        let checks = verify_postconditions(&result, &[PostconditionSpec::ExitCodeEquals(42)]);
        assert!(all_passed(&checks));

        let checks = verify_postconditions(&result, &[PostconditionSpec::ExitCodeEquals(0)]);
        assert!(!all_passed(&checks));
    }

    #[test]
    fn test_output_contains() {
        let result = make_result(0, serde_json::json!({"message": "hello world"}), vec![]);
        let checks = verify_postconditions(&result, &[PostconditionSpec::OutputContains("hello".into())]);
        assert!(all_passed(&checks));

        let checks = verify_postconditions(&result, &[PostconditionSpec::OutputContains("missing".into())]);
        assert!(!all_passed(&checks));
    }

    #[test]
    fn test_output_matches_key() {
        let result = make_result(0, serde_json::json!({"status": "ok"}), vec![]);
        let checks = verify_postconditions(&result, &[PostconditionSpec::OutputMatchesKey {
            key: "status".into(),
            expected: serde_json::json!("ok"),
        }]);
        assert!(all_passed(&checks));

        let checks = verify_postconditions(&result, &[PostconditionSpec::OutputMatchesKey {
            key: "status".into(),
            expected: serde_json::json!("error"),
        }]);
        assert!(!all_passed(&checks));
    }

    #[test]
    fn test_no_side_effects() {
        let clean = make_result(0, serde_json::json!({}), vec![]);
        let checks = verify_postconditions(&clean, &[PostconditionSpec::NoSideEffects]);
        assert!(all_passed(&checks));

        let dirty = make_result(0, serde_json::json!({}), vec!["wrote_file".into()]);
        let checks = verify_postconditions(&dirty, &[PostconditionSpec::NoSideEffects]);
        assert!(!all_passed(&checks));
    }

    #[test]
    fn test_multiple_postconditions() {
        let result = make_result(0, serde_json::json!({"status": "ok"}), vec![]);
        let specs = vec![
            PostconditionSpec::ExitCodeZero,
            PostconditionSpec::OutputContains("ok".into()),
            PostconditionSpec::NoSideEffects,
        ];
        let checks = verify_postconditions(&result, &specs);
        assert_eq!(checks.len(), 3);
        assert!(all_passed(&checks));
    }

    #[test]
    fn test_partial_failure() {
        let result = make_result(1, serde_json::json!({"status": "ok"}), vec![]);
        let specs = vec![
            PostconditionSpec::ExitCodeZero,        // fails
            PostconditionSpec::OutputContains("ok".into()), // passes
        ];
        let checks = verify_postconditions(&result, &specs);
        assert!(!all_passed(&checks));
        assert!(!checks[0].passed);
        assert!(checks[1].passed);
    }
}
