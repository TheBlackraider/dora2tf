use anyhow::Result;
use aws_sdk_ec2::Client;

#[derive(Debug, Clone)]
pub struct SecurityGroup {
    pub id:          String,
    pub name:        String,
    pub description: String,
    pub vpc_id:      String,
    pub ingress:     Vec<Rule>,
    pub egress:      Vec<Rule>,
    pub tags:        std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub protocol:    String,
    pub from_port:   i32,
    pub to_port:     i32,
    pub cidr_blocks: Vec<String>,
    pub source_sg:   Option<String>,
    pub description: String,
}

pub async fn scan_security_groups(client: &Client) -> Result<Vec<SecurityGroup>> {
    let resp = client.describe_security_groups().send().await?;
    let mut sgs = Vec::new();

    for sg in resp.security_groups() {
        let name = sg.group_name().unwrap_or("unnamed").to_string();
        let id   = sg.group_id().map(|s| s.to_string()).unwrap_or_default();

        let ingress: Vec<Rule> = sg.ip_permissions().iter().map(|perm| {
            let cidrs: Vec<String> = perm.ip_ranges().iter().map(|r| r.cidr_ip().map(|s| s.to_string()).unwrap_or_default()).collect();
            let source = perm.user_id_group_pairs().iter()
                .find_map(|p| p.group_id().map(|s| s.to_string()));
            Rule {
                protocol:    perm.ip_protocol().unwrap_or("tcp").into(),
                from_port:   perm.from_port().unwrap_or(0),
                to_port:     perm.to_port().unwrap_or(65535),
                cidr_blocks: cidrs,
                source_sg:   source,
                description: perm.ip_ranges().iter()
                    .find_map(|r| r.description().map(|s| s.to_string()))
                    .unwrap_or_default(),
            }
        }).collect();

        let egress: Vec<Rule> = sg.ip_permissions_egress().iter().map(|perm| {
            let cidrs: Vec<String> = perm.ip_ranges().iter().map(|r| r.cidr_ip().map(|s| s.to_string()).unwrap_or_default()).collect();
            Rule {
                protocol:    perm.ip_protocol().unwrap_or("tcp").into(),
                from_port:   perm.from_port().unwrap_or(0),
                to_port:     perm.to_port().unwrap_or(65535),
                cidr_blocks: cidrs,
                source_sg:   None,
                description: String::new(),
            }
        }).collect();

        let tags: std::collections::HashMap<String, String> = sg.tags().iter()
            .filter_map(|t| { let k = t.key()?; let v = t.value().unwrap_or_default(); Some((k.to_string(), v.to_string())) })
            .collect();

        sgs.push(SecurityGroup {
            id,
            name,
            description: sg.description().map(|s| s.to_string()).unwrap_or_default(),
            vpc_id:      sg.vpc_id().map(|s| s.to_string()).unwrap_or_default(),
            ingress,
            egress,
            tags,
        });
    }

    Ok(sgs)
}
