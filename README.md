# github-app

[![Build Status](https://api.cirrus-ci.com/github/jasonwhite/github-app.svg?branch=master)](https://cirrus-ci.com/github/jasonwhite/github-app) [![Crates.io](https://img.shields.io/crates/v/github-app.svg)](https://crates.io/crates/github-app) [![Documentation](https://docs.rs/github-app/badge.svg)](https://docs.rs/github-app)

A Rust library for creating GitHub Apps.

## Features

 * Verifies the signature of webhook payloads to ensure that they are actually
   coming from GitHub.

 * Automatic JSON deserialization of webhook payloads.

 * Handles app authorization with GitHub transparently. Renewal of the JSON Web
   Token (JWT) is handled automatically when using a `ClientPool`.

 * Composable with [Hyper](https://github.com/hyperium/hyper) services.

## Usage

```rust
use std::io;
use std::net::SocketAddr;

use futures::{future, Future};
use github_app::{self, Event, GithubApp};
use tokio;

#[derive(Clone)]
struct MyApp;

impl GithubApp for MyApp {
    type Error = io::Error;
    type Future = Box<dyn Future<Item = (), Error = Self::Error> + Send>;

    fn call(&mut self, event: Event) -> Self::Future {
        println!("{:#?}", event);
        Box::new(future::ok(()))
    }
}

fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tokio::run(github_app::server(&addr, MyApp).map_err(|e| println!("{}", e)))
}
```

You can run this example with:

```
cargo run --example minimal
```

## Examples

 1. [`minimal`](/examples/minimal.rs) - The same minimal example as above. This
    does not do any payload verification or logging.

 2. [`echo`](/examples/echo.rs) - Verifies payloads and prints out the
    deserialized payload for every webhook it receives.

 3. [`delete_merged_branches`](/examples/delete_merged_branches.rs) - Deletes
    branches as soon as their associated pull request is merged.


## References

 - https://developer.github.com/v3/activity/events/types/
 - https://developer.github.com/apps/building-github-apps/authenticating-with-github-apps/

## License

[MIT license](LICENSE)

## Thanks

This was developed at [Environmental Systems Research
Institute](http://www.esri.com/) (Esri) who have graciously allowed me to retain
the copyright and publish it as open source software.
