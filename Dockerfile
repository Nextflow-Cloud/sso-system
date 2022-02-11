FROM node:16.13.2-bullseye
WORKDIR /sso-system
COPY . /sso-system 
RUN yarn install
ENTRYPOINT [ "node", "index.js" ]
EXPOSE 3000
