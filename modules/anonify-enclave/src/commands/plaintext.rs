use frame_common::{state_types::UserCounter, AccessPolicy};
use serde::{Deserialize, Serialize};
use std::string::String;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandPlaintext<AP: AccessPolicy> {
    #[serde(deserialize_with = "AP::deserialize")]
    pub access_policy: AP,
    pub runtime_params: serde_json::Value,
    pub cmd_name: String,
    pub counter: UserCounter,
}

impl<AP> Default for CommandPlaintext<AP>
where
    AP: AccessPolicy,
{
    fn default() -> Self {
        Self {
            access_policy: AP::default(),
            runtime_params: serde_json::Value::Null,
            cmd_name: String::default(),
            counter: UserCounter::default(),
        }
    }
}

impl<AP> CommandPlaintext<AP>
where
    AP: AccessPolicy,
{
    pub fn access_policy(&self) -> &AP {
        &self.access_policy
    }

    pub fn cmd_name(&self) -> &str {
        &self.cmd_name
    }

    pub fn counter(&self) -> UserCounter {
        self.counter
    }
}
