use anyhow::Result;
use std::fmt::Write;
use crate::scanner::vpc::{VpcInfo, Subnet};

/// Generate just a VPC (for shared.tf).
pub fn generate_vpc_only(vpc: &VpcInfo, output: &mut String) -> Result<()> {
    let name = super::tf_name(&vpc.name);
    writeln!(output, "resource \"aws_vpc\" \"{}\" {{", name)?;
    writeln!(output, "  cidr_block = \"{}\"", vpc.cidr)?;
    writeln!(output, "  enable_dns_hostnames = true")?;
    writeln!(output, "  tags = {{")?;
    for (k, v) in &vpc.tags {
        if !v.is_empty() {
            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
        }
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}\n")?;
    Ok(())
}

/// Generate just a subnet referencing its VPC (for shared.tf).
pub fn generate_subnet_only(vpc: &VpcInfo, sub: &Subnet, output: &mut String) -> Result<()> {
    let vname = super::tf_name(&vpc.name);
    let sname = super::tf_name(&sub.name);
    writeln!(output, "resource \"aws_subnet\" \"{}\" {{", sname)?;
    writeln!(output, "  vpc_id            = aws_vpc.{}.id", vname)?;
    writeln!(output, "  cidr_block        = \"{}\"", sub.cidr)?;
    writeln!(output, "  availability_zone = \"{}\"", sub.availability_zone)?;
    writeln!(output, "  map_public_ip_on_launch = {}", sub.map_public_ip)?;
    writeln!(output, "  tags = {{ Name = \"{}\" }}", sub.name)?;
    writeln!(output, "}}\n")?;
    Ok(())
}
