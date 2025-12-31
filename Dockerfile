# Build stage
FROM docker.io/library/node:20-slim AS builder

# Metadata
LABEL maintainer="DarkCoder Team <dara.daranaki@gmail.com>"
LABEL version="0.7.0"
LABEL description="DarkCoder - AI Security Operations Agent with CVE Intelligence"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
  python3 \
  make \
  g++ \
  git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Set up npm global package folder
RUN mkdir -p /usr/local/share/npm-global
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Copy source code
COPY . /home/node/app
WORKDIR /home/node/app

# Install dependencies and build packages with memory optimization
# Using npm install instead of npm ci for better cross-version compatibility
RUN NODE_OPTIONS='--max-old-space-size=8192' npm install --ignore-scripts \
  && node scripts/generate-git-commit-info.js \
  && NODE_OPTIONS='--max-old-space-size=8192' npm run build --workspaces \
  && npm pack -w @darkcoder/darkcoder --pack-destination ./packages/cli/dist \
  && npm pack -w @darkcoder/darkcoder-core --pack-destination ./packages/core/dist

# Runtime stage
FROM docker.io/library/node:20-slim

ARG SANDBOX_NAME="qwen-code-sandbox"
ARG CLI_VERSION_ARG="0.7.0"
ENV SANDBOX="$SANDBOX_NAME"
ENV CLI_VERSION=$CLI_VERSION_ARG

# Metadata for runtime image
LABEL maintainer="DarkCoder Team <dara.daranaki@gmail.com>"
LABEL version="0.7.0"
LABEL description="DarkCoder Runtime - AI Security Operations Agent with Live CVE Intelligence"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
  python3 \
  man-db \
  curl \
  dnsutils \
  less \
  jq \
  bc \
  gh \
  git \
  unzip \
  rsync \
  ripgrep \
  procps \
  psmisc \
  lsof \
  socat \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Set up npm global package folder
RUN mkdir -p /usr/local/share/npm-global
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Copy the entire built application from builder (including node_modules)
COPY --from=builder /home/node/app /app
WORKDIR /app

# Link the CLI globally so 'darkcoder' command is available
RUN cd /app/packages/cli && npm link

# Use ENTRYPOINT so docker run arguments are passed to darkcoder
ENTRYPOINT ["darkcoder"]
# Default to interactive mode if no arguments provided
CMD []
