FROM openjdk:14-slim

RUN apt-get update && apt-get install -y \
    curl \
    procps \
    unzip \
    wget


# Install nodejs
RUN curl -sL https://deb.nodesource.com/setup_13.x | bash -
RUN apt-get install -y nodejs

# Install Chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-unstable --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Disable the download of Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

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
COPY ./server.js ./server.js

# Run service
ENTRYPOINT ["npm", "start"]
