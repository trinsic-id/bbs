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
macro_rules! hex {
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
    pub total_message_count: usize,
    pub proof: String,
    pub result: Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) struct Generators {
    pub bp: String,
    pub q1: String,
    pub q2: String,
    #[serde(rename = "MsgGenerators")]
    pub msg_generators: Vec<String>,
}

/*
{
  "caseName": "MapMessageToScalar fixture",
  "dst": "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f",
  "cases": [
    {
      "message": "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
      "scalar": "360097633e394c22601426bd9f8d5b95f1c64f89689deee230e817925dee4724"
    },
    {
      "message": "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
      "scalar": "1e68fedccc3d68236c7e4ccb508ebb3da5d5de1864eac0a0f683de22752e6d28"
    },
    {
      "message": "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
      "scalar": "4d20cb09c2ac1e1c572e83f355b90ea996c7a6ab98a03a98098c1abeb8c7a195"
    },
    {
      "message": "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943",
      "scalar": "038f1892656f7753eb2be1ab3679dd0d0331fb5e7be0f72550dbe22b0f36df02"
    },
    {
      "message": "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151",
      "scalar": "144cb3d17379b746217a93910a8ca07ca7248be3d1972b562010a4e09a27b7f3"
    },
    {
      "message": "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc",
      "scalar": "5da7360f11d5133c6ed6e54c1a1fd230a2c9256d5b6be0b41219808bfc964d28"
    },
    {
      "message": "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2",
      "scalar": "100e944c0a82da79b062a9cc2b014d16b345b4e4624e7408106fe282da0635cc"
    },
    {
      "message": "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91",
      "scalar": "2004000723ef8997256f5f2a86cbef353c3034ab751092033fa0c0a844d639af"
    },
    {
      "message": "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416",
      "scalar": "68a1f58bb5aaa3bc89fba6c40ccd761879fdadf336565cef9812ed5dba5d56ca"
    },
    {
      "message": "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
      "scalar": "1aefbeb8e206723a37fc2e7f8eded8227d960bed44b7089fec0d7e6da93e5d38"
    }
  ]
}
 */

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
    pub count: usize,
    pub scalars: Vec<String>,
}
