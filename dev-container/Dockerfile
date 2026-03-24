FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG USER=dev
ARG UID=1000
ARG GID=1000
ARG APT_MIRROR=

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i \
            -e "s|http://archive.ubuntu.com/ubuntu/|${APT_MIRROR}|" \
            -e "s|http://security.ubuntu.com/ubuntu/|${APT_MIRROR}|" \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bash \
        bash-completion \
        bat \
        bear \
        bison \
        build-essential \
        ca-certificates \
        ccache \
        clang-20 \
        clang-format-20 \
        clangd-20 \
        cmake \
        cpp-14 \
        cppcheck \
        curl \
        fd-find \
        file \
        flex \
        fzf \
        g++-14 \
        gcc-14 \
        gdb \
        git \
        google-perftools \
        heaptrack \
        hyperfine \
        iwyu \
        jq \
        less \
        libc++-20-dev \
        libc++abi-20-dev \
        libclang-rt-20-dev \
        libpq-dev \
        libstdc++-14-dev \
        libtool \
        libunwind-20-dev \
        lldb \
        locales \
        linux-tools-common \
        linux-tools-generic \
        lsof \
        lsb-release \
        ncurses-term \
        ninja-build \
        nodejs \
        npm \
        openssh-client \
        ocrmypdf \
        parallel \
        perl \
        pkg-config \
        poppler-utils \
        postgresql \
        procps \
        python3 \
        qpdf \
        ripgrep \
        rsync \
        sed \
        sqlite3 \
        strace \
        sudo \
        tesseract-ocr \
        tesseract-ocr-eng \
        tmux \
        mupdf-tools \
        valgrind \
        vim \
        wget \
        llvm-20; \
    locale-gen en_US.UTF-8; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    git clone --depth 1 --branch v3.8.0 https://github.com/catchorg/Catch2.git /tmp/catch2; \
    cmake -S /tmp/catch2 -B /tmp/catch2/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCATCH_INSTALL_DOCS=OFF \
        -DCATCH_INSTALL_EXTRAS=ON; \
    cmake --build /tmp/catch2/build; \
    cmake --install /tmp/catch2/build; \
    rm -rf /tmp/catch2

RUN set -eux; \
    if [ -x /usr/bin/batcat ] && [ ! -e /usr/local/bin/bat ]; then \
        ln -s /usr/bin/batcat /usr/local/bin/bat; \
    fi; \
    if [ -x /usr/bin/fdfind ] && [ ! -e /usr/local/bin/fd ]; then \
        ln -s /usr/bin/fdfind /usr/local/bin/fd; \
    fi

RUN set -eux; \
    existing_group="$(getent group "${GID}" | cut -d: -f1 || true)"; \
    if [ -z "${existing_group}" ]; then \
        if getent group "${USER}" >/dev/null; then \
            groupmod --gid "${GID}" "${USER}"; \
        else \
            groupadd --gid "${GID}" "${USER}"; \
        fi; \
    fi; \
    existing_user="$(getent passwd "${UID}" | cut -d: -f1 || true)"; \
    if id -u "${USER}" >/dev/null 2>&1; then \
        usermod --uid "${UID}" --gid "${GID}" -s /bin/bash "${USER}"; \
    elif [ -n "${existing_user}" ]; then \
        usermod --login "${USER}" --home "/home/${USER}" --move-home "${existing_user}"; \
        usermod --uid "${UID}" --gid "${GID}" -s /bin/bash "${USER}"; \
    else \
        useradd --uid "${UID}" --gid "${GID}" -m -s /bin/bash "${USER}"; \
    fi; \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USER}"; \
    chmod 0440 "/etc/sudoers.d/${USER}"

RUN install -d -o "${UID}" -g "${GID}" \
    "/home/${USER}/.cargo" \
    "/home/${USER}/.local/bin" \
    "/home/${USER}/.npm-global" \
    "/home/${USER}/.rustup"

ENV CARGO_HOME="/home/${USER}/.cargo" \
    NPM_CONFIG_PREFIX="/home/${USER}/.npm-global" \
    PATH="/home/${USER}/.local/bin:/home/${USER}/.npm-global/bin:/home/${USER}/.cargo/bin:${PATH}" \
    RUSTUP_HOME="/home/${USER}/.rustup"

COPY --chown=${UID}:${GID} install-rust.sh rust-toolchain.toml /tmp/stellar-core/

RUN chmod 0755 /tmp/stellar-core/install-rust.sh

RUN su - "${USER}" -c 'set -eux; \
    export CARGO_HOME="/home/'"${USER}"'/.cargo"; \
    export RUSTUP_HOME="/home/'"${USER}"'/.rustup"; \
    export PATH="${CARGO_HOME}/bin:${PATH}"; \
    cd /tmp/stellar-core; \
    ./install-rust.sh; \
    . "${CARGO_HOME}/env"; \
    rustup component add rustfmt clippy rust-src; \
    rustup target add wasm32-unknown-unknown wasm32v1-none; \
    rustup toolchain install stable --profile minimal --component rustfmt --component clippy --component rust-src --target wasm32-unknown-unknown --target wasm32v1-none; \
    cargo install --locked cargo-cache --version 0.8.3; \
    cargo install --locked cargo-sweep --version 0.7.0'

RUN su - "${USER}" -c 'set -eux; \
    export NPM_CONFIG_PREFIX="/home/'"${USER}"'/.npm-global"; \
    npm install -g @anthropic-ai/claude-code @openai/codex; \
    npm cache clean --force'

RUN rm -rf /tmp/stellar-core

RUN install -d -o "${UID}" -g "${GID}" \
    "/home/${USER}/.claude" \
    "/home/${USER}/.codex" \
    "/home/${USER}/stellar-core"

COPY --chown=${UID}:${GID} dev-container/tmux.conf /home/${USER}/.tmux.conf
COPY --chown=${UID}:${GID} dev-container/osc52-tmux /home/${USER}/.local/bin/osc52-tmux
COPY --chown=${UID}:${GID} dev-container/perf-wrapper.sh /home/${USER}/.local/bin/perf
COPY --chown=${UID}:${GID} dev-container/pdf-extract.sh /home/${USER}/.local/bin/pdf-extract
RUN chmod 0755 /home/${USER}/.local/bin/osc52-tmux /home/${USER}/.local/bin/perf /home/${USER}/.local/bin/pdf-extract
COPY dev-container/project-title.sh /etc/profile.d/project-title.sh
RUN grep -qxF 'source /etc/profile.d/project-title.sh' /etc/bash.bashrc \
    || echo 'source /etc/profile.d/project-title.sh' >> /etc/bash.bashrc
RUN if [ -f "/home/${USER}/.bashrc" ]; then \
        grep -qxF 'source /etc/profile.d/project-title.sh' "/home/${USER}/.bashrc" \
            || echo 'source /etc/profile.d/project-title.sh' >> "/home/${USER}/.bashrc"; \
    else \
        cp /etc/skel/.bashrc "/home/${USER}/.bashrc"; \
        echo 'source /etc/profile.d/project-title.sh' >> "/home/${USER}/.bashrc"; \
        chown "${UID}:${GID}" "/home/${USER}/.bashrc"; \
    fi

ENV CC=clang-20 \
    CLANG_VERSION=20 \
    CXX=clang++-20

USER ${USER}
WORKDIR /home/${USER}/stellar-core
