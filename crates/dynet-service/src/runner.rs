use std::process::{Command, Stdio};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait ServiceRunner {
    fn run(&self, command: &str, args: &[String]) -> Result<CommandOutput, String>;

    fn stream(&self, command: &str, args: &[String]) -> Result<(), String> {
        let output = self.run(command, args)?;
        if output.success {
            if !output.stdout.is_empty() {
                println!("{}", output.stdout);
            }
            return Ok(());
        }
        Err(command_failure(command, args, &output))
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct HostRunner;

impl ServiceRunner for HostRunner {
    fn run(&self, command: &str, args: &[String]) -> Result<CommandOutput, String> {
        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|error| format!("failed running {command}: {error}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    fn stream(&self, command: &str, args: &[String]) -> Result<(), String> {
        let status = Command::new(command)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| format!("failed running {command}: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{command} exited with {status}"))
        }
    }
}

pub(crate) fn run_required(
    runner: &impl ServiceRunner,
    command: &str,
    args: &[String],
) -> Result<CommandOutput, String> {
    let output = runner.run(command, args)?;
    if output.success {
        Ok(output)
    } else {
        Err(command_failure(command, args, &output))
    }
}

fn command_failure(command: &str, args: &[String], output: &CommandOutput) -> String {
    let detail = if output.stderr.is_empty() {
        output.stdout.as_str()
    } else {
        output.stderr.as_str()
    };
    format!("{} {} failed: {}", command, args.join(" "), detail)
}
