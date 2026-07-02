use anyhow::Result;
use aws_sdk_ec2::Client;

#[derive(Debug, Clone)]
pub struct VpcInfo {
    pub id:      String,
    pub name:    String,
    pub cidr:    String,
    pub subnets: Vec<Subnet>,
    pub tags:    std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub id:               String,
    pub name:             String,
    pub cidr:             String,
    pub availability_zone: String,
    pub map_public_ip:    bool,
}

pub async fn scan_vpcs(client: &Client) -> Result<Vec<VpcInfo>> {
    let vpc_resp = client.describe_vpcs().send().await?;
    let sub_resp = client.describe_subnets().send().await?;
    let mut vpcs = Vec::new();

    for vpc in vpc_resp.vpcs() {
        let vpc_id = vpc.vpc_id().map(|s| s.to_string()).unwrap_or_default();
        let name = vpc.tags().iter()
            .find(|t| t.key().map(|k| k == "Name").unwrap_or(false))
            .and_then(|t| t.value().map(|s| s.to_string()))
            .unwrap_or_else(|| vpc_id.clone());

        let subnets: Vec<Subnet> = sub_resp.subnets().iter()
            .filter(|s| s.vpc_id().map(|v| v == &vpc_id).unwrap_or(false))
            .map(|s| {
                let sname = s.tags().iter()
                    .find(|t| t.key().map(|k| k == "Name").unwrap_or(false))
                    .and_then(|t| t.value().map(|s| s.to_string()))
                    .unwrap_or_else(|| s.subnet_id().map(|s| s.to_string()).unwrap_or_default());
                Subnet {
                    id:                s.subnet_id().map(|s| s.to_string()).unwrap_or_default(),
                    name:              sname,
                    cidr:              s.cidr_block().map(|s| s.to_string()).unwrap_or_default(),
                    availability_zone: s.availability_zone().map(|s| s.to_string()).unwrap_or_default(),
                    map_public_ip:     s.map_public_ip_on_launch().unwrap_or(false),
                }
            })
            .collect();

        let tags: std::collections::HashMap<String, String> = vpc.tags().iter()
            .filter_map(|t| { let k = t.key()?; let v = t.value().unwrap_or_default(); Some((k.to_string(), v.to_string())) })
            .collect();

        vpcs.push(VpcInfo {
            id:   vpc_id,
            name,
            cidr: vpc.cidr_block().map(|s| s.to_string()).unwrap_or_default(),
            subnets,
            tags,
        });
    }

    Ok(vpcs)
}
