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

//! A simple app that prints out the payloads it receives from GitHub. This
//! might be useful for exploring the GitHub API.

use std::io;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;

use futures::{future, Future};
use log;
use pretty_env_logger;
use structopt::StructOpt;

use github_app::{server, Event, GithubApp};

struct State {
    app_secret: Option<String>,
}

#[derive(Clone)]
struct Echo {
    state: Arc<State>,
}

impl Echo {
    pub fn new(state: Arc<State>) -> Self {
        Echo { state }
    }
}

impl GithubApp for Echo {
    type Error = io::Error;
    type Future = Box<dyn Future<Item = (), Error = Self::Error> + Send>;

    fn secret(&self) -> Option<&str> {
        self.state.app_secret.as_ref().map(String::as_str)
    }

    fn call(&mut self, event: Event) -> Self::Future {
        println!("{:#?}", event);
        Box::new(future::ok(()))
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
}

impl Args {
    fn main(self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize logging.
        pretty_env_logger::formatted_timed_builder()
            .filter_module("echo", self.log_level)
            .filter_module("github_app", self.log_level)
            .init();

        // Create the app.
        let app = Echo::new(Arc::new(State {
            app_secret: self.app_secret,
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
