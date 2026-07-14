use anyhow::Result;
use std::fmt::Write;
use crate::scanner::iam::IamRole;

pub fn generate(roles: &[IamRole], output: &mut String) -> Result<()> {
    for role in roles {
        let rname = super::tf_name(&role.name);

        writeln!(output, "resource \"aws_iam_role\" \"{}\" {{", rname)?;
        writeln!(output, "  name = \"{}\"", role.name)?;
        // Use heredoc for raw JSON — avoids jsonencode() and escaping issues
        writeln!(output, "  assume_role_policy = <<EOF")?;
        write!(output, "{}", role.assume_role_policy)?;
        writeln!(output, "EOF")?;
        writeln!(output, "  tags = {{")?;
        writeln!(output, "    ManagedBy = \"dora2tf\"")?;
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;

        for arn in &role.managed_policies {
            let pol_name = super::tf_name(
                &arn.split('/').last().unwrap_or("policy")
            );
            let aname = format!("{}_{}", rname, pol_name);
            writeln!(output, "resource \"aws_iam_role_policy_attachment\" \"{}\" {{", aname)?;
            writeln!(output, "  role       = aws_iam_role.{}.name", rname)?;
            writeln!(output, "  policy_arn = \"{}\"", arn)?;
            writeln!(output, "}}\n")?;
        }

        for pol in &role.inline_policies {
            let pname = super::tf_name(
                &format!("{}_{}", role.name, pol.name),
            );
            writeln!(output, "resource \"aws_iam_role_policy\" \"{}\" {{", pname)?;
            writeln!(output, "  name   = \"{}\"", pol.name)?;
            writeln!(output, "  role   = aws_iam_role.{}.name", rname)?;
            writeln!(output, "  policy = <<EOF")?;
            write!(output, "{}", pol.document)?;
            writeln!(output, "EOF")?;
            writeln!(output, "}}\n")?;
        }
    }

    Ok(())
}
