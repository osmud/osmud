# Copyright 2018 osMUD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM ubuntu:xenial

ENV LEDE_VERSION=v17.01.4

RUN set -ex \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
    subversion g++ zlib1g-dev build-essential git python rsync man-db \
    libncurses5-dev gawk gettext unzip file libssl-dev wget openssl \
    ca-certificates libcurl4-openssl-dev vim libjson-c-dev pkg-config sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash lede && echo "lede:lede" | chpasswd && adduser lede sudo

USER lede

RUN set -ex \
    && cd /home/lede \
    && git clone -b $LEDE_VERSION https://git.lede-project.org/source.git lede \
    && cd lede \
    && ./scripts/feeds update -a \
    && ./scripts/feeds install -a

WORKDIR /home/lede

CMD ["/bin/bash"]
