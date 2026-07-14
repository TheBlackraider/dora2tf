use anyhow::Result;
use std::fmt::Write;
use crate::scanner::sg::SecurityGroup;

/// Generate one SG with its rules (for shared.tf).
pub fn generate_one(sg: &SecurityGroup, output: &mut String) -> Result<()> {
    let name = super::tf_name(&sg.name);

    writeln!(output, "resource \"aws_security_group\" \"{}\" {{", name)?;
    writeln!(output, "  name        = \"{}\"", sg.name)?;
    writeln!(output, "  description = \"{}\"", sg.description)?;
    writeln!(output, "  vpc_id      = \"{}\"", sg.vpc_id)?;
    writeln!(output, "  tags = {{")?;
    for (k, v) in &sg.tags {
        if !v.is_empty() {
            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
        }
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}\n")?;

    for rule in &sg.ingress {
        let rn = format!("{}_ingress_{}_{}", name, rule.protocol, rule.from_port);
        writeln!(output, "resource \"aws_security_group_rule\" \"{}\" {{", rn)?;
        writeln!(output, "  type              = \"ingress\"")?;
        writeln!(output, "  from_port         = {}", rule.from_port)?;
        writeln!(output, "  to_port           = {}", rule.to_port)?;
        writeln!(output, "  protocol          = \"{}\"", rule.protocol)?;
        writeln!(output, "  security_group_id = aws_security_group.{}.id", name)?;
        if let Some(ref src) = rule.source_sg {
            writeln!(output, "  source_security_group_id = \"{}\"", src)?;
        } else if !rule.cidr_blocks.is_empty() {
            writeln!(output, "  cidr_blocks       = [")?;
            for c in &rule.cidr_blocks {
                writeln!(output, "    \"{}\",", c)?;
            }
            writeln!(output, "  ]")?;
        }
        writeln!(output, "}}\n")?;
    }
    writeln!(output)?;

    Ok(())
}
