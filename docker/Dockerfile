FROM openjdk:14-slim

RUN apt-get update && apt-get install -y \
    curl \
    dumb-init \
    unzip

# Install nodejs
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash -
RUN apt-get install -y nodejs

WORKDIR /opt/app
ENV IB_GATEWAY_BIN="/opt/app/bin/run.sh"
ENV IB_GATEWAY_CONF="/opt/app/root/conf.yaml"

# Download client portal and extract
ADD https://download2.interactivebrokers.com/portal/clientportal.gw.zip clientportal.gw.zip
RUN unzip clientportal.gw.zip

# edit conf.yaml (need to allow ip 172.* for docker)
RUN sed -i 's/allow:/allow:\n        - 172.*/' root/conf.yaml
# edit conf.yaml (need to allow ip 10.244.0.* for digital ocean)
RUN sed -i 's/allow:/allow:\n        - 10.244.*/' root/conf.yaml

# Install package requirements
COPY ./package-lock.json ./package-lock.json
COPY ./package.json ./package.json
RUN npm ci

# Copy server code
COPY ./server ./server

# Run service
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server"]
