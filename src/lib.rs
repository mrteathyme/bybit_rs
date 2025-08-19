use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{de::Unexpected, Deserialize, Serialize};

pub const MAINNET: &str = "https://api.bybit.com";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Params<T> {
    Get(T),
    Post(T)
}

impl<T:Serialize> Params<T> {
    pub fn to_string(&self) -> anyhow::Result<String> {
        match self {
            Params::Get(query) => Ok(serde_qs::to_string(query)?),
            Params::Post(body) => Ok(serde_json::to_string(body)?),
        }
    }
}

pub fn sign<T: Serialize>(secret: &str, timestamp: &DateTime<Utc>, api_key: &str, recv_window: &Duration, params: &Params<T>) -> anyhow::Result<String> {
    let timestamp = timestamp.timestamp_millis().to_string();
    let recv_window = recv_window.as_millis().to_string();
    let params = params.to_string()?;
    let signature = format!("{timestamp}{api_key}{recv_window}{params}");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    Ok(hex::encode(ring::hmac::sign(&key, signature.as_bytes())))
}

#[derive(Debug, Clone, Deserialize)]
pub struct Response<T> 
{
    #[serde(rename = "retCode")]
    pub return_code: i32,
    #[serde(rename = "retMsg")]
    pub return_message: String,
    pub result: T,
    #[serde(rename = "retExtInfo")]
    pub return_extended_info: Option<serde_json::Value>,
    pub time: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum AccountType {
    UNIFIED,
    FUND,
    CONTRACT,
    SPOT
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BybitBalance {
    coin: String,
    #[serde(rename = "transferBalance")]
    transfer_balance: String,
    #[serde(rename = "walletBalance")]
    wallet_balance: String,
    bonus: String,
}


pub struct BybitRequest<T: for<'a> serde::Deserialize<'a>>(http::Request<String>,std::marker::PhantomData<T>);

#[derive(Debug, Deserialize)]
pub struct BybitError {

    #[serde(rename = "retCode")]
    code: BybitErrorCode,

    #[serde(rename = "retMsg")]
    message: Option<String>
}
impl std::error::Error for BybitError {}
impl std::fmt::Display for BybitError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let message = match &self.message {
            Some(data) => {data},
            None => "N/A"
        };
        write!(f, "BybitError: {} ({})", message, self.code.0)
    }
}

impl<T: for<'a> serde::Deserialize<'a>> BybitRequest<T> {
    fn new(req: http::Request<String>) -> Self {
        Self(req,std::marker::PhantomData)
    }
    pub async fn send<F, R, E>(self, func: F) -> anyhow::Result<T>
    where F: Fn(http::Request<String>) -> R,
        R: std::future::Future<Output = Result<bytes::Bytes, E>>,
        anyhow::Error: From<E>
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum _Response<T> {
            Ok(Response<T>),
            Err(BybitError)
        }
        let response: _Response<T> = serde_json::from_slice(&func(self.0).await?)?;
        match response {
            _Response::Ok(data) => Ok(data.result),
            _Response::Err(err) => Err(err.into())
        }
    }
}

//really hacky solution to avoid having to write custom desieralizers due to rest specification being violated (200 code errors) for every response type, by erroring
//out on zero response codes it wont deserialize to the error type despite their structure being identical, for real though fuck devs that dont respect HTTP codes and verbs
#[derive(Debug, Clone)]
pub struct BybitErrorCode(i32);

impl<'de> Deserialize<'de> for BybitErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
            let code = i32::deserialize(deserializer)?;
            if code == 0 {
                return Err(serde::de::Error::invalid_value(Unexpected::Signed(0), &"non-zero error code"));
            }
            Ok(BybitErrorCode(code))
    }
}

pub trait IntoPostRequest: serde::Serialize {
    const DOMAIN: &'static str;
    const ENDPOINT: &'static str;
    type Response: for<'a> serde::Deserialize<'a>;
    fn uri(&self) -> String {
        format!("{}{}", Self::DOMAIN, Self::ENDPOINT)
    }
    fn as_request(
        &self,
        key: &str,
        secret: &str,
        recv_window: &Duration
    ) -> anyhow::Result<BybitRequest<Self::Response>> {
        let timestamp = Utc::now();
        let params = Params::Post(self);
        Ok(BybitRequest::new(http::request::Builder::new()
            .method("POST")
            .header("X-BAPI-API-KEY", key)
            .header("X-BAPI-SIGN", sign(secret,&timestamp, key,recv_window,&params)?)
            .header("X-BAPI-TIMESTAMP", timestamp.timestamp_millis().to_string())
            .header("X-BAPI-RECV-WINDOW", recv_window.as_millis().to_string())
            .uri(self.uri())
            .body(serde_json::to_string(self)?)?))
    }
}

pub trait IntoGetRequest: serde::Serialize {
    const DOMAIN: &'static str;
    const ENDPOINT: &'static str;
    type Response: for<'a> serde::Deserialize<'a>;
    fn uri(&self) -> String {
        format!("{}{}", Self::DOMAIN, Self::ENDPOINT)
    }
    fn as_request(
        &self,
        key: &str,
        secret: &str,
        recv_window: &Duration
    ) -> anyhow::Result<BybitRequest<Self::Response>> {
        let timestamp = Utc::now();
        let params = Params::Get(self);
        Ok(BybitRequest::new(http::request::Builder::new()
            .method("GET")
            .header("X-BAPI-API-KEY", key)
            .header("X-BAPI-SIGN", sign(secret,&timestamp, key,recv_window,&params)?)
            .header("X-BAPI-TIMESTAMP", timestamp.timestamp_millis().to_string())
            .header("X-BAPI-RECV-WINDOW", recv_window.as_millis().to_string())
            .uri(format!("{}?{}",self.uri(), params.to_string()?))
            .body(String::new())?))
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    api_key: String,
    secret: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FundingBalance {
    #[serde(rename = "accountType")]
    pub account_type: AccountType,
    #[serde(rename = "memberId")]
    pub member_id: String,
    pub balance: Vec<BybitBalance>,
}

impl Client {
    pub fn new(api_key: String, secret: String) -> Self {
        Self { api_key, secret }
    }

    pub fn get_funding_balance(&mut self, coin: Option<String>, recv_window: &Duration) -> BybitRequest<FundingBalance>{
            #[derive(Serialize, Debug)]
            struct FundingRequest {
                #[serde(rename = "accountType")]
                account_type: AccountType,
                coin: Option<String>,
                #[serde(rename = "withBonus")]
                with_bonus: i32,
            }

            impl IntoGetRequest for FundingRequest {
                const DOMAIN: &'static str = MAINNET;
                const ENDPOINT: &'static str = "/v5/asset/transfer/query-account-coins-balance";
                type Response = FundingBalance;
            }

            let request = FundingRequest {
                        account_type: AccountType::FUND,
                        coin,
                        with_bonus: 0,
            };

            request.as_request(&self.api_key,&self.secret, recv_window).unwrap() 
    }

}
