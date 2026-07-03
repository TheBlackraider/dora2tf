use anyhow::Result;
use std::fmt::Write;
use crate::scanner::iam::IamRole;
use urlencoding::decode;

pub fn generate(roles: &[IamRole], output: &mut String) -> Result<()> {
    for role in roles {
        let rname = super::tf_name(&role.name);
        writeln!(output, "resource \"aws_iam_role\" \"{}\" {{", rname)?;
        writeln!(output, "  name = \"{}\"", role.name)?;
        writeln!(output, "  assume_role_policy = {}", decode(&role.assume_role_policy).unwrap());
        writeln!(output, "  tags = {{")?;
        writeln!(output, "    ManagedBy = \"dora2tf\"")?;
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;

        for (i, arn) in role.managed_policies.iter().enumerate() {
            writeln!(output, "resource \"aws_iam_role_policy_attachment\" \"{}_{}\" {{", rname, i)?;
            writeln!(output, "  role       = aws_iam_role.{}.name", rname)?;
            writeln!(output, "  policy_arn = \"{}\"", arn)?;
            writeln!(output, "}}\n")?;
        }

        for pol in &role.inline_policies {
            let pname = super::tf_name(&pol.name);
            writeln!(output, "resource \"aws_iam_role_policy\" \"{}_{}\" {{", rname, pname)?;
            writeln!(output, "  name   = \"{}\"", pol.name)?;
            writeln!(output, "  role   = aws_iam_role.{}.name", rname)?;
            writeln!(output, "  policy = jsonencode({})", pol.document)?;
            writeln!(output, "}}\n")?;
        }
    }

    Ok(())
}
