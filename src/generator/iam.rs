use anyhow::Result;
use std::fmt::Write;
use crate::scanner::iam::IamRole;
use urlencoding::decode;

pub fn generate(roles: &[IamRole], output: &mut String) -> Result<()> {
    for role in roles {
        // IAM role names are unique within an account — use name directly
        // but append a short suffix from the name itself as a safety net
        let rname = super::tf_unique_name(&role.name, &role.name);

        writeln!(output, "resource \"aws_iam_role\" \"{}\" {{", rname)?;
        writeln!(output, "  name = \"{}\"", role.name)?;
        writeln!(output, "  assume_role_policy = {}", decode(&role.assume_role_policy).unwrap());
        writeln!(output, "  tags = {{")?;
        writeln!(output, "    ManagedBy = \"dora2tf\"")?;
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;

        for (_i, arn) in role.managed_policies.iter().enumerate() {
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
            let pname = super::tf_unique_name(
                &format!("{}_{}", role.name, pol.name),
                &pol.name,
            );
            writeln!(output, "resource \"aws_iam_role_policy\" \"{}\" {{", pname)?;
            writeln!(output, "  name   = \"{}\"", pol.name)?;
            writeln!(output, "  role   = aws_iam_role.{}.name", rname)?;
            writeln!(output, "  policy = jsonencode({})", pol.document)?;
            writeln!(output, "}}\n")?;
        }
    }

    Ok(())
}
