# Nextflow SSO authentication system

### About
Built on MERN stack, the Nextflow SSO authentication system allows you to log in to all Nextflow services with a single account.
* Flexible and versatile
* Clean and fluid interface
* Fast

This is the Express-based backend. For the React-based frontend, please check out [sso-system-client](https://github.com/Nextflow-Cloud/sso-system-client).

### Setup without Docker
This service uses MongoDB for its backend management, so you will need a MongoDB cluster or self hosted MongoDB server both of which for the pricing, and downloads page respectively can be found at [MongoDB's Website](https://www.mongodb.com/)
* Get a working MongoDB cluster or MongoDB self-hosted server
* Go in a terminal and run node index.js or npm start
* Enjoy the service

### Setup with Docker
This service uses MongoDB for its backend management, so you will need a MongoDB cluster or self hosted MongoDB server both of which for the pricing, and downloads page respectively can be found at [MongoDB's Website](https://www.mongodb.com/).
You will also need to install docker which can be installed on many linux distributions by the convienence script provided by Docker.

#### Get the convienence script:

```shell
curl -fsSL https://get.docker.com -o get-docker.sh
```

#### Run the convience script and install Docker:

```shell
sh ./get-docker.sh
```

#### Get a working instance of a MongoDB cluster or get a MongoDB self-hosted server

#### Run our docker build script

```shell
./build.sh
```

* Enjoy the service at last :)


### Contribute
Nextflow Cloud Technologies is committed to open-source software and free use. This means that you are free to view, modify, contribute, and support the project. Making a pull request with something useful is highly encouraged as this project is made possible by contributors like you who support the project.
