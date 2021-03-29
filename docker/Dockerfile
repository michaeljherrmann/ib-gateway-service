FROM openjdk:14-slim

RUN apt-get update && apt-get install -y \
    curl \
    dumb-init \
    procps \
    unzip \
    wget

# Maybe need these for chromium
# apt-get install libpangocairo-1.0-0 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 libnss3 libcups2 libxss1 libxrandr2  libasound2 libatk1.0-0 libgtk-3-0

# Install nodejs
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash -
RUN apt-get install -y nodejs

# Install Chrome (will install deps for Chromium)
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-unstable --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Uncomment to disable the download of Chromium
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
COPY ./server ./server

# Use dumb-init to prevent zombie processes from puppeteer
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Run service
CMD ["node", "server"]
