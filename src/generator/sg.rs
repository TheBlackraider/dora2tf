use anyhow::Result;
use std::fmt::Write;

use crate::scanner::sg::SecurityGroup;

pub fn generate(sgs: &[SecurityGroup], output: &mut String) -> Result<()> {
    for sg in sgs {
        let name = super::tf_name(&sg.name);
        writeln!(output, "resource \"aws_security_group\" \"{}_{}\" {{", name, sg.vpc_id)?;
        writeln!(output, "  name        = \"{}\"", sg.name)?;
        writeln!(output, "  description = \"{}\"", sg.description)?;
        writeln!(output, "  vpc_id      = \"{}\"", sg.vpc_id)?;

        writeln!(output, "  tags = {{")?;
        writeln!(output, "    Name      = \"{}\"", sg.name)?;
        writeln!(output, "    ManagedBy = \"dora2tf\"")?;
        for (k, v) in &sg.tags {
            if k != "Name" && !v.is_empty() {
                writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
            }
        }
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;

        // Ingress rules
        for (i, rule) in sg.ingress.iter().enumerate() {
            writeln!(output, "resource \"aws_security_group_rule\" \"{}_ingress_{}_{}\" {{", name, i, rule.to_port)?;
            writeln!(output, "  type              = \"ingress\"")?;
            writeln!(output, "  from_port         = {}", rule.from_port)?;
            writeln!(output, "  to_port           = {}", rule.to_port)?;
            writeln!(output, "  protocol          = \"{}\"", rule.protocol)?;
            writeln!(output, "  security_group_id = aws_security_group.{}.id", name)?;

            if let Some(ref src) = rule.source_sg {
                writeln!(output, "  source_security_group_id = \"{}\"", src)?;
            } else if !rule.cidr_blocks.is_empty() {
                writeln!(output, "  cidr_blocks       = [")?;
                for cidr in &rule.cidr_blocks {
                    writeln!(output, "    \"{}\",", cidr)?;
                }
                writeln!(output, "  ]")?;
            }
            writeln!(output, "}}\n")?;
        }

        // Egress rules
        for (i, rule) in sg.egress.iter().enumerate() {
            writeln!(output, "resource \"aws_security_group_rule\" \"{}_egress_{}\" {{", name, rule.to_port)?;
            writeln!(output, "  type              = \"egress\"")?;
            writeln!(output, "  from_port         = {}", rule.from_port)?;
            writeln!(output, "  to_port           = {}", rule.to_port)?;
            writeln!(output, "  protocol          = \"{}\"", rule.protocol)?;
            writeln!(output, "  security_group_id = aws_security_group.{}.id", name)?;
            writeln!(output, "  cidr_blocks       = [\"0.0.0.0/0\"]")?;
            writeln!(output, "}}\n")?;
        }
    }

    Ok(())
}
