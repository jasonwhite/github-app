// Copyright (c) 2019 Jason White
// Copyright (c) 2019 Mike Lubinets
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
mod logger;

pub use logger::Logger;

pub use github_types as types;

pub use types::{AppEvent, Event, EventType};

use std::collections::HashMap;
use std::convert::{From, Infallible};
use std::fmt;
use std::net::SocketAddr;
use std::str::{from_utf8, FromStr};
use std::sync::Mutex;

use crypto_mac::MacError;
use derive_more::{Display, From};
use futures::{future, Future, StreamExt};
use hmac::{Hmac, Mac};
use hubcaps::{Credentials, InstallationTokenGenerator};
use hyper::{self, server::conn::AddrStream, service::make_service_fn, Server};
use hyper::{
    header::{self, HeaderValue},
    http::StatusCode,
    service::Service,
    Body, Request, Response,
};
use reqwest::r#async::Client;
use sha1::Sha1;

// Re-export these to avoid forcing users to add a dependency on hubcaps.
use futures::task::{Context, Poll};
pub use hubcaps::{self, Github, JWTCredentials};
use std::pin::Pin;

/// A trait that a Github app must implement.
pub trait GithubApp: Clone {
    type Error: fmt::Display;
    type Future: Future<Output = Result<(), Self::Error>> + Send;

    /// The secret that was created when the app was created. This is used to
    /// verify that webhook payloads are really coming from GitHub.
    ///
    /// If this returns `None` (the default), then signatures are not verified
    /// for payloads.
    fn secret(&self) -> Option<&str> {
        None
    }

    /// Called when an event is received.
    fn call(&mut self, payload: Event) -> Self::Future;
}

/// Wraps an app in a Hyper service which can be used to run the server.
pub struct App<T> {
    app: T,
}

impl<T> App<T> {
    pub fn new(app: T) -> Self {
        App { app }
    }
}

impl<T> App<T>
where
    T: GithubApp + Sync + Send + 'static,
{
    async fn handle_request(
        mut app: T,
        req: Request<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let payload = match parse_request(req, app.secret()).await {
            Ok(p) => p,
            Err(err) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(err.to_string().into())
            }
        };

        if let Err(err) = app.call(payload).await {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(err.to_string().into());
        };

        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
    }
}

impl<T> Service<Request<Body>> for App<T>
where
    T: GithubApp + Sync + Send + 'static,
{
    type Response = Response<Body>;
    type Error = hyper::http::Error;
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let app = self.app.clone();
        let response = Self::handle_request(app, req);
        Box::pin(response)
    }
}

#[derive(From, Display)]
pub enum PayloadError {
    Hyper(hyper::Error),
    Json(serde_json::Error),
    Mac(MacError),
}

#[derive(Display)]
pub enum Error {
    #[display(fmt = "Invalid or missing Content-Type")]
    ContentType,

    #[display(fmt = "Invalid X-Github-Event")]
    InvalidEvent,

    #[display(fmt = "Missing X-Github-Event")]
    MissingEvent,

    #[display(fmt = "Missing X-Hub-Signature")]
    MissingSignature,

    #[display(fmt = "Invalid X-Hub-Signature")]
    InvalidSignature,

    #[display(fmt = "HTTP Error")]
    Http(hyper::http::Error),

    Payload(PayloadError),
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Error::Payload(PayloadError::Hyper(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Payload(PayloadError::Json(e))
    }
}

impl From<MacError> for Error {
    fn from(e: MacError) -> Self {
        Error::Payload(PayloadError::Mac(e))
    }
}

impl From<hyper::http::Error> for Error {
    fn from(e: hyper::http::Error) -> Self {
        Error::Http(e)
    }
}

/// Parses a Hyper request for a Github event.
///
/// This handles hmac signature verification to ensure that the payload actually
/// came from Github.
async fn parse_request(
    req: Request<Body>,
    secret: Option<&str>,
) -> Result<Event, Error> {
    if req.headers().get(header::CONTENT_TYPE)
        != Some(&HeaderValue::from_static("application/json"))
    {
        return Err(Error::ContentType);
    }

    // Parse the event type.
    let event = req
        .headers()
        .get("X-Github-Event")
        .ok_or_else(|| Error::MissingEvent)
        .and_then(move |header| {
            from_utf8(header.as_bytes())
                .map_err(|_| Error::InvalidEvent)
                .and_then(|s| {
                    EventType::from_str(s).map_err(|_| Error::InvalidEvent)
                })
        })?;

    // Parse the signature
    let signature = req
        .headers()
        .get("X-Hub-Signature")
        .ok_or_else(|| Error::MissingSignature)
        .and_then(move |header| {
            from_utf8(header.as_bytes())
                .map_err(|_| Error::InvalidSignature)
                .and_then(|s| {
                    Signature::from_str(s).map_err(|_| Error::InvalidSignature)
                })
        })?;

    let mut mac =
        secret.map(|s| Hmac::<Sha1>::new_varkey(s.as_bytes()).unwrap());

    // Parse the JSON payload.
    let mut buf = Vec::new();

    let mut body = req.into_body();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;

        if let Some(mac) = mac.as_mut() {
            mac.input(&chunk);
        }

        buf.extend(chunk);
    }

    if let Some(mac) = mac {
        mac.verify(signature.digest())?;
    }

    parse_event(event, &buf).map_err(Error::from)
}

fn parse_event(
    event_type: EventType,
    slice: &[u8],
) -> Result<Event, serde_json::Error> {
    Ok(match event_type {
        EventType::Ping => Event::Ping(serde_json::from_slice(slice)?),
        EventType::CheckRun => Event::CheckRun(serde_json::from_slice(slice)?),
        EventType::CheckSuite => {
            Event::CheckSuite(serde_json::from_slice(slice)?)
        }
        EventType::CommitComment => {
            Event::CommitComment(serde_json::from_slice(slice)?)
        }
        EventType::Create => Event::Create(serde_json::from_slice(slice)?),
        EventType::Delete => Event::Delete(serde_json::from_slice(slice)?),
        EventType::GitHubAppAuthorization => {
            Event::GitHubAppAuthorization(serde_json::from_slice(slice)?)
        }
        EventType::Gollum => Event::Gollum(serde_json::from_slice(slice)?),
        EventType::Installation => {
            Event::Installation(serde_json::from_slice(slice)?)
        }
        EventType::InstallationRepositories => {
            Event::InstallationRepositories(serde_json::from_slice(slice)?)
        }
        EventType::IntegrationInstallation => {
            Event::IntegrationInstallation(serde_json::from_slice(slice)?)
        }
        EventType::IntegrationInstallationRepositories => {
            Event::IntegrationInstallationRepositories(serde_json::from_slice(
                slice,
            )?)
        }
        EventType::IssueComment => {
            Event::IssueComment(serde_json::from_slice(slice)?)
        }
        EventType::Issues => Event::Issues(serde_json::from_slice(slice)?),
        EventType::Label => Event::Label(serde_json::from_slice(slice)?),
        EventType::PullRequest => {
            Event::PullRequest(serde_json::from_slice(slice)?)
        }
        EventType::PullRequestReview => {
            Event::PullRequestReview(serde_json::from_slice(slice)?)
        }
        EventType::PullRequestReviewComment => {
            Event::PullRequestReviewComment(serde_json::from_slice(slice)?)
        }
        EventType::Push => Event::Push(serde_json::from_slice(slice)?),
        EventType::Repository => {
            Event::Repository(serde_json::from_slice(slice)?)
        }
        EventType::Watch => Event::Watch(serde_json::from_slice(slice)?),
        _ => panic!(format!("Unimplemented event type: {}", event_type)),
    })
}

const USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// A pool of JWT credentials, indexed by the installation ID.
pub struct ClientPool {
    pool: Mutex<HashMap<u64, InstallationTokenGenerator>>,

    /// The Reqwest HTTP client.
    client: Client,

    /// The Github API URL.
    api: String,

    creds: JWTCredentials,
}

impl ClientPool {
    pub fn new(api: String, creds: JWTCredentials) -> Self {
        ClientPool {
            pool: Mutex::new(HashMap::new()),
            client: Client::new(),
            api,
            creds,
        }
    }

    /// Gets a Github client for the given installation ID.
    pub fn get(&self, installation: u64) -> Github {
        let mut pool = self.pool.lock().unwrap();

        let token_generator = pool
            .entry(installation)
            .or_insert_with(|| {
                InstallationTokenGenerator::new(
                    installation,
                    self.creds.clone(),
                )
            })
            .clone();

        Github::custom(
            self.api.clone(),
            USER_AGENT,
            Credentials::InstallationToken(token_generator),
            self.client.clone(),
        )
    }
}

/// Webhook signature.
#[derive(Debug, Clone)]
struct Signature {
    digest: Vec<u8>,
}

impl Signature {
    pub fn new(digest: Vec<u8>) -> Signature {
        Signature { digest }
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl FromStr for Signature {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut splits = s.trim().splitn(2, '=');

        match (splits.next(), splits.next()) {
            (Some(method), Some(digest)) => {
                // GitHub doesn't use anything else besides sha1 at the moment.
                if method != "sha1" {
                    return Err(());
                }

                Ok(Signature::new(hex::decode(digest).map_err(|_| ())?))
            }
            _ => Err(()),
        }
    }
}

pub fn server<T>(
    addr: &SocketAddr,
    app: T,
) -> impl Future<Output = Result<(), hyper::Error>>
where
    T: GithubApp + Sync + Send + Unpin + 'static,
{
    // Create our service factory.
    let new_service = make_service_fn(move |socket: &AddrStream| {
        // Create our app.
        let service = App::new(app.clone());

        // Add logging middleware
        let service = Logger::new(socket.remote_addr(), service);

        future::ready(Ok::<_, Infallible>(service))
    });

    // Create the server.
    let server = Server::bind(addr).serve(new_service);

    log::info!("Listening on {}", server.local_addr());

    server
}
