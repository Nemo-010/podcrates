//! The text of an error of a command line: `OPTION: what is wrong; fix:
//! what to do`. One form for each program, so that a user and a script
//! find the option and the fix in the same place.

use crate::rules::{Fault, Kind, faults};

/// `OPTION: WHAT; fix: FIX`. `option` is the flag, the argument or the
/// command that is wrong; `what` says what is wrong; `fix` is one
/// instruction.
pub fn fault(option: &str, what: &str, fix: &str) -> String {
    let what = what.trim().trim_end_matches(['.', ';']);
    let fix = fix.trim().trim_end_matches(['.', ';']);
    format!("{option}: {what}; fix: {fix}")
}

/// The faults of an error text by the text rules: the part before `fix:`
/// is a description, and the fix is an instruction of a procedure.
pub fn check(text: &str) -> Vec<Fault> {
    match text.split_once("; fix: ") {
        Some((what, fix)) => {
            let mut out = faults(what, Kind::Description);
            out.extend(faults(fix, Kind::Procedure));
            out
        }
        None => faults(text, Kind::Description),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_names_the_option_what_is_wrong_and_the_fix() {
        assert_eq!(
            fault("--timeout", "the value 0 is not a number of seconds.", "give a number from 1 to 3600"),
            "--timeout: the value 0 is not a number of seconds; fix: give a number from 1 to 3600"
        );
    }

    #[test]
    fn the_fix_of_an_error_has_the_limit_of_a_procedure() {
        let long = "word ".repeat(21);
        assert!(check(&fault("-x", "bad", &long)).iter().any(|f| matches!(f, Fault::Long { limit: 20, .. })));
        assert!(check(&fault("-x", &long, "give one")).is_empty());
    }
}
