use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub case_name: String,
    pub signer_key_pair: KeyPair,
    pub header: String,
    pub messages: Vec<String>,
    pub signature: String,
    pub result: Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    pub secret_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPairFixture {
    pub case_name: String,
    pub key_material: String,
    pub key_info: String,
    pub key_pair: KeyPair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Result {
    pub valid: bool,
    pub reason: Option<String>,
}

#[macro_export]
macro_rules! fixture {
    ($type:ty,$path:expr) => {
        serde_json::from_reader::<std::io::BufReader<std::fs::File>, $type>(std::io::BufReader::new(
            std::fs::File::open(std::path::Path::new("spec/tooling/fixtures/fixture_data").join($path)).unwrap(),
        ))
        .unwrap()
    };
}

#[macro_export]
macro_rules! hex_decode {
    ($input:expr) => {
        hex::decode($input).unwrap()
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Proof {
    pub case_name: String,
    pub signer_public_key: String,
    pub header: String,
    pub presentation_header: String,
    pub revealed_messages: BTreeMap<u32, String>,
    pub proof: String,
    pub result: Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) struct Generators {
    pub bp: String,
    pub q1: String,
    #[serde(rename = "MsgGenerators")]
    pub msg_generators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MapMessageToScalar {
    pub case_name: String,
    pub dst: String,
    pub cases: Vec<MapMessageToScalarCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MapMessageToScalarCase {
    pub message: String,
    pub scalar: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HashToScalar {
    pub case_name: String,
    pub message: String,
    pub dst: String,
    pub scalar: String,
}
