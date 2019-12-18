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

//! An app that deletes branches as soon as they are merged via a pull request.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use futures::{compat::Future01CompatExt, future, Future, TryFutureExt};
use log;
use nom_pem;
use pretty_env_logger;
use structopt::StructOpt;

use github_app::{
    server, AppEvent, ClientPool, Event, GithubApp, JWTCredentials,
};

struct State {
    app_secret: Option<String>,
    client_pool: ClientPool,
}

#[derive(Clone)]
struct DeleteMergedBranches {
    state: Arc<State>,
}

impl DeleteMergedBranches {
    pub fn new(state: Arc<State>) -> Self {
        DeleteMergedBranches { state }
    }
}

impl GithubApp for DeleteMergedBranches {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;

    fn secret(&self) -> Option<&str> {
        self.state.app_secret.as_ref().map(String::as_str)
    }

    fn call(&mut self, event: Event) -> Self::Future {
        match event {
            Event::PullRequest(pr) => {
                // Only delete merged branches.
                if !pr.pull_request.merged {
                    return Box::pin(future::ok(()));
                }

                if let Some(client) =
                    pr.installation().map(|id| self.state.client_pool.get(id))
                {
                    log::info!(
                        "Deleting branch '{}' in: {}",
                        pr.pull_request.head.git_ref,
                        pr.pull_request.html_url
                    );

                    Box::pin(
                        client
                            .repo(pr.repository.owner.login, pr.repository.name)
                            .git()
                            .delete_reference(format!(
                                "heads/{}",
                                pr.pull_request.head.git_ref
                            ))
                            .compat()
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("GitHub response error: {}", e),
                                )
                            }),
                    )
                } else {
                    Box::pin(future::ok(()))
                }
            }
            _ => Box::pin(future::ok(())),
        }
    }
}

#[derive(StructOpt)]
struct Args {
    /// Host or address to listen on.
    #[structopt(long = "addr", default_value = "0.0.0.0:8080")]
    addr: SocketAddr,

    /// Logging level to use. By default, uses `info`.
    #[structopt(long = "log-level", default_value = "info")]
    log_level: log::LevelFilter,

    /// The GitHub app secret. Used to verify the signatures of payloads coming
    /// from GitHub. If not specified, payload signatures are not verified.
    #[structopt(long = "secret")]
    app_secret: Option<String>,

    /// The GitHub APP ID. This is the unique number given to the app;
    /// generated when the app is created.
    #[structopt(long = "id")]
    app_id: u64,

    #[structopt(long = "key")]
    key: PathBuf,

    #[structopt(long = "api", default_value = "https://api.github.com")]
    api: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::from_args();

    // Initialize logging.
    pretty_env_logger::formatted_timed_builder()
        .filter_module("delete_merged_branches", args.log_level)
        .filter_module("github_app", args.log_level)
        .init();

    // Read the PEM file.
    let key = fs::read(args.key)?;
    let key = nom_pem::decode_block(&key).unwrap();

    // Create the app.
    let app = DeleteMergedBranches::new(Arc::new(State {
        app_secret: args.app_secret,
        client_pool: ClientPool::new(
            args.api,
            JWTCredentials::new(args.app_id, key.data)?,
        ),
    }));

    // Run the app.
    server(&args.addr, app).await?;

    Ok(())
}
