// Copyright (c) 2019 Jason White
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
use std::process::exit;
use std::sync::Arc;

use futures::{future, Future};
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
    type Future = Box<dyn Future<Item = (), Error = Self::Error> + Send>;

    fn secret(&self) -> Option<&str> {
        self.state.app_secret.as_ref().map(String::as_str)
    }

    fn call(&mut self, event: Event) -> Self::Future {
        match event {
            Event::PullRequest(pr) => {
                // Only delete merged branches.
                if !pr.pull_request.merged {
                    return Box::new(future::ok(()));
                }

                if let Some(client) =
                    pr.installation().map(|id| self.state.client_pool.get(id))
                {
                    log::info!(
                        "Deleting branch '{}' in: {}",
                        pr.pull_request.head.commit_ref,
                        pr.pull_request.html_url
                    );

                    Box::new(
                        client
                            .repo(pr.repository.owner.login, pr.repository.name)
                            .git()
                            .delete_reference(format!(
                                "heads/{}",
                                pr.pull_request.head.commit_ref
                            ))
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("GitHub response error: {}", e),
                                )
                            }),
                    )
                } else {
                    Box::new(future::ok(()))
                }
            }
            _ => Box::new(future::ok(())),
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

impl Args {
    fn main(self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize logging.
        pretty_env_logger::formatted_timed_builder()
            .filter_module("delete_merged_branches", self.log_level)
            .filter_module("github_app", self.log_level)
            .init();

        // Read the PEM file.
        let key = fs::read(self.key)?;
        let key = nom_pem::decode_block(&key).unwrap();

        // Create the app.
        let app = DeleteMergedBranches::new(Arc::new(State {
            app_secret: self.app_secret,
            client_pool: ClientPool::new(
                self.api,
                JWTCredentials::new(self.app_id, key.data)?,
            ),
        }));

        // Run the app.
        tokio::run(server(&self.addr, app).map_err(|e| log::error!("{}", e)));

        Ok(())
    }
}

fn main() {
    let exit_code = if let Err(err) = Args::from_args().main() {
        log::error!("{}", err);
        1
    } else {
        0
    };

    exit(exit_code);
}
