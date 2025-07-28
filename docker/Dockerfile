FROM openjdk:26-slim

RUN apt-get update && apt-get install -y \
    curl \
    dumb-init \
    unzip

# Install nodejs
RUN curl -sL https://deb.nodesource.com/setup_22.x | bash -
RUN apt-get install -y nodejs

# Install yarn
RUN npm install -g yarn
RUN corepack enable

WORKDIR /opt/app
ENV IB_GATEWAY_BIN="/opt/app/bin/run.sh"
ENV IB_GATEWAY_CONF="root/conf.yaml"

# Download client portal and extract
ADD https://download2.interactivebrokers.com/portal/clientportal.gw.zip clientportal.gw.zip
RUN unzip clientportal.gw.zip

# edit conf.yaml (need to allow ip 172.* for docker)
RUN sed -i 's/allow:/allow:\n        - 172.*/' root/conf.yaml
# edit conf.yaml (need to allow ip 184.* for docker)
RUN sed -i 's/allow:/allow:\n        - 184.*/' root/conf.yaml
# edit conf.yaml (need to allow ip 10.244.0.* for digital ocean)
RUN sed -i 's/allow:/allow:\n        - 10.244.*/' root/conf.yaml

# Install package requirements
COPY yarn.lock package.json .yarnrc.yml ./
RUN yarn install --immutable

# Copy server code
COPY ./server ./server

# Run service
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server"]
