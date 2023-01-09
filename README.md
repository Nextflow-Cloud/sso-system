# Nextflow SSO authentication system

## About
Introducing the all-new server, which has been rewritten from the ground up for a strongly typed and fast system.

Formerly built on MERN stack, the Nextflow SSO authentication system allows you to log in to all Nextflow services with a single account.
* Flexible and versatile
* Clean and fluid interface
* Fast

The entire Nextflow SSO authentication system is currently being overhauled. We are introducing a new type of stack: WARM. WARM stands for [Warp](https://crates.io/crates/warp), [Astro](https://astro.build), [Rust](https://rust-lang.org), and [MongoDB](https://mongodb.com). 

This is the Rust-based backend. For the Preact-based frontend, please check out [sso-system-client](https://github.com/Nextflow-Cloud/sso-system-client). There are currently no plans to overhaul the client yet. 

## Hosting the server

### Set up database
This service uses MongoDB as a database, so you will need a MongoDB cluster or self-hosted MongoDB server. More information can be found on [their website](https://mongodb.com/).

### Run with Docker
If you need an included database server, use Docker. Docker is highly recommended to contain Obviously, you will also need to install Docker. It can be installed on most Linux distributions using a convenience script or package manager. Please check [their website](https://docs.docker.com/engine/install/) for more detailed documentation on how to install Docker and configuration.

You will need to have the Docker Compose plugin installed along with Docker itself.

Copy `docker-compose.example.yml` into your own `docker-compose.yml` and modify it as needed. If you have an existing MongoDB instance, you may remove the `sso-system-mongodb` entry and point the `MONGODB_URI` and `MONGODB_DATABASE` variables to your own instance. Otherwise, keep the entry to use the included database server.

Populate the other environment variables as necessary. Currently, all variables are required for intended operation of the server.

To start the container, run `docker compose up -d` (with sudo as necessary).

### Run without Docker 
Although Docker is the preferred method of running the server, you can do so without Docker as well. You will need to run your own MongoDB instance or obtain a cluster. 

Before running, you should populate the environment variables with the following:
* `MONGODB_URI`: URI pointing to the MongoDB instance or cluster.
* `MONGODB_DATABASE`: The database to use in MongoDB.
* `JWT_SECRET`: A 32-byte key to encode JWT tokens.
* `HCAPTCHA_SECRET`: A secret from hCaptcha to verify hCaptcha tokens.
* `CORS_ORIGINS`: A list of origins to allow CORS requests from, separated by commas.
* `HOST`: The host to bind the server to.

Currently, all variables are required for intended operation of the server.

After doing so, run `cargo run --release` to build and run the server. It may take a while to build, especially on ARM64 systems.

## Contribute
Nextflow Cloud Technologies is committed to open-source software and free use. This means that you are free to view, modify, contribute, and support the project. Making a pull request with something useful is highly encouraged as this project is made possible by contributors like you who support the project.

* `prod`: Most stable branch: used in production [here](https://sso.nextflow.cloud). 
* `main`: Beta or release preview: mostly stable and likely will be pushed to production with a couple fixes.
* `dev`: Active development: expect a variety of unstable and/or unfinished features and fixes.
