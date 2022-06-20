# Nextflow SSO authentication system

### About
Built on MERN stack, the Nextflow SSO authentication system allows you to log in to all Nextflow services with a single account.
* Flexible and versatile
* Clean and fluid interface
* Fast

This is the Rust-based backend. For the Preact-based frontend, please check out [sso-system-client](https://github.com/Nextflow-Cloud/sso-system-client).

The backend has been rewritten from the ground up for a strongly typed and fast system. It is built using the Warp library. 

**Docker is not yet available for the new version yet. Please hold while we produce a stable version to work with Docker, or you can feel free to make your own.**

### Set up database
This service uses the MongoDB database, so you will need a MongoDB cluster or self hosted MongoDB server. Both the pricing and downloads page can be found on [their website](https://www.mongodb.com/).

### Run without Docker
* Obtain a working MongoDB cluster or MongoDB self-hosted server
* Go in a terminal and run `cargo run --release` (it may take a while to build, especially on ARM64 systems)
* Enjoy the service

### Run with Docker
Obviously, you will also need to install Docker which can be installed on most Linux distributions by the using the convienence script provided. Please check their website for more detailed documentation regarding Docker.

#### Get the convienence script:

```shell
curl -fsSL https://get.docker.com -o get-docker.sh
```

#### Run the convenience script and install Docker:

```shell
chmod +x get-docker.sh
./get-docker
```

#### Obtain a working instance of a MongoDB cluster or get a MongoDB self-hosted server

#### Run our Docker build script

```shell
sudo ./build.sh
```

* Enjoy the service at last :)


### Contribute
Nextflow Cloud Technologies is committed to open-source software and free use. This means that you are free to view, modify, contribute, and support the project. Making a pull request with something useful is highly encouraged as this project is made possible by contributors like you who support the project.

* prod: Most stable branch - used in production [here](https://secure.nextflow.cloud). 
* main: Beta/release preview - mostly stable and likely will be pushed to production with a couple fixes.
* dev: Active development - expect a variety of unstable and/or unfinished features and fixes.
