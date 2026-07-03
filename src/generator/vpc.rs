use anyhow::Result;
use std::fmt::Write;
use crate::scanner::vpc::VpcInfo;

pub fn generate(vpcs: &[VpcInfo], output: &mut String) -> Result<()> {

    let mut i = 0;

    for vpc in vpcs {
        let vname = super::tf_name(&vpc.name);
        writeln!(output, "resource \"aws_vpc\" \"{}_{}\" {{", vname, &i)?;
        writeln!(output, "  cidr_block = \"{}\"", vpc.cidr)?;
        writeln!(output, "  enable_dns_hostnames = true")?;
        writeln!(output, "  tags = {{")?;
        writeln!(output, "    Name      = \"{}\"", vpc.name)?;
        writeln!(output, "    ManagedBy = \"dora2tf\"")?;
        for (k, v) in &vpc.tags {
            if k != "Name" && !v.is_empty() {
                writeln!(output, "    {} = \"{}\"", k, v)?;
            }
        }
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;

        for subnet in &vpc.subnets {
            let sname = super::tf_name(&subnet.name);
            writeln!(output, "resource \"aws_subnet\" \"{}_{}\" {{", sname, &subnet.availability_zone)?;
            writeln!(output, "  vpc_id            = aws_vpc.{}.id", vname)?;
            writeln!(output, "  cidr_block        = \"{}\"", subnet.cidr)?;
            writeln!(output, "  availability_zone = \"{}\"", subnet.availability_zone)?;
            writeln!(output, "  map_public_ip_on_launch = {}", subnet.map_public_ip)?;
            writeln!(output, "  tags = {{")?;
            writeln!(output, "    Name      = \"{}\"", subnet.name)?;
            writeln!(output, "    ManagedBy = \"dora2tf\"")?;
            writeln!(output, "  }}")?;
            writeln!(output, "}}\n")?;
        }

        i+= 1;
    }

    Ok(())
}
