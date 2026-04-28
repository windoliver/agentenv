use crate::model::CommandAction;

pub fn parse_command(input: &str) -> Result<CommandAction, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty command".to_owned());
    }

    let mut parts = trimmed.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("destroy"), Some(env), None) => Ok(CommandAction::DestroyEnv(env.to_owned())),
        (Some("destroy"), None, _) => Err("destroy requires an env name".to_owned()),
        _ => Err(format!("unknown command `{trimmed}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_command;
    use crate::model::CommandAction;

    #[test]
    fn parses_destroy_command() {
        assert_eq!(
            parse_command("destroy myapp").expect("parse destroy"),
            CommandAction::DestroyEnv("myapp".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_command() {
        let error = parse_command("policy-add github_read myapp").expect_err("unknown command");
        assert!(error.contains("unknown command"));
    }

    #[test]
    fn rejects_empty_command() {
        let error = parse_command("   ").expect_err("empty command");
        assert!(error.contains("empty command"));
    }
}
