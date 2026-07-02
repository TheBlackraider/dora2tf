use anyhow::Result;
use aws_sdk_iam::Client;

#[derive(Debug, Clone)]
pub struct IamRole {
    pub name:              String,
    pub assume_role_policy: String,
    pub managed_policies:  Vec<String>,
    pub inline_policies:   Vec<InlinePolicy>,
    pub tags:              std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct InlinePolicy {
    pub name:     String,
    pub document: String,
}

pub async fn scan_roles(client: &Client) -> Result<Vec<IamRole>> {
    let resp = client.list_roles().send().await?;
    let mut roles = Vec::new();

    for role in resp.roles() {
        let role_name = role.role_name().to_string();

        // Assume role policy document
        let assume_doc = client
            .get_role()
            .role_name(&role_name)
            .send()
            .await
            .ok()
            .and_then(|r| r.role().and_then(|rl| {
                rl.assume_role_policy_document().map(|s| s.to_string())
            }))
            .unwrap_or_else(|| "{}".into());

        // Managed policies
        let managed: Vec<String> = client
            .list_attached_role_policies()
            .role_name(&role_name)
            .send()
            .await
            .ok()
            .map(|r| {
                r.attached_policies().iter()
                    .filter_map(|p| p.policy_arn().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Inline policies
        let inline_names: Vec<String> = client
            .list_role_policies()
            .role_name(&role_name)
            .send()
            .await
            .ok()
            .map(|r| r.policy_names().iter().map(|n| n.to_string()).collect())
            .unwrap_or_default();

        let mut inline_policies = Vec::new();
        for pname in &inline_names {
            if let Ok(pol_resp) = client
                .get_role_policy()
                .role_name(&role_name)
                .policy_name(pname)
                .send()
                .await
            {
                inline_policies.push(InlinePolicy {
                    name:     pname.clone(),
                    document: pol_resp.policy_document().to_string(),
                });
            }
        }

        let tags: std::collections::HashMap<String, String> = role.tags().iter()
            .map(|t| (t.key().to_string(), t.value().to_string()))
            .collect();

        roles.push(IamRole {
            name: role_name,
            assume_role_policy: assume_doc,
            managed_policies: managed,
            inline_policies,
            tags,
        });
    }

    Ok(roles)
}
