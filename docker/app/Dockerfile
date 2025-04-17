FROM stagex/bash:5.2.21@sha256:cb58f55d268fbe7ef629cda86e3a8af893066e4af7f26ef54748b6ad47bdaa66 AS bash
FROM stagex/make:4.4@sha256:df43f0cf3ac1ad91bf91baefb539e8df42c11b0954a6e2498322a5467deb81e3 AS make
FROM stagex/musl:sx2024.09.0@sha256:ad351b875f26294562d21740a3ee51c23609f15e6f9f0310e0994179c4231e1d AS musl
FROM stagex/zlib:1.3.1@sha256:96b4100550760026065dac57148d99e20a03d17e5ee20d6b32cbacd61125dbb6 AS zlib
FROM stagex/core-git:sx2025.03.0@sha256:5b0ce8741532026bb7e6f2302855a93057a27a7f38e596e9a7fb0e782f04d0f6 AS git
FROM stagex/ca-certificates:sx2024.09.0@sha256:33787f1feb634be4232a6dfe77578c1a9b890ad82a2cf18c11dd44507b358803 AS ca-certificates


# enclave specific dependencies
FROM ghcr.io/mdehoog/aws-nitro-enclaves-sdk-bootstrap@sha256:6e5e53bd47370dbc1920208e93d222533a36f9f5dc85615591cbfe56a03312b0 AS bootstrap
FROM stagex/openssl:3.0.12@sha256:2c1a9d8fcc6f52cb11a206f380b17d74c1079f04cbb08071a4176648b4df52c1 AS openssl
FROM stagex/eif_build:sx2024.09.0@sha256:291653f1ca528af48fd05858749c443300f6b24d2ffefa7f5a3a06c27c774566 AS eif_build
FROM stagex/libunwind:1.7.2@sha256:97ee6068a8e8c9f1c74409f80681069c8051abb31f9559dedf0d0d562d3bfc82 AS libunwind
FROM stagex/coreutils:9.4@sha256:1955f532d8923b5e17f60635c994bd9577bb3e6bccb5da702a69e79070bae0a9 AS coreutils
FROM stagex/gcc:13.1.0@sha256:439bf36289ef036a934129d69dd6b4c196427e4f8e28bc1a3de5b9aab6e062f0 AS gcc

FROM scratch AS base
COPY --from=stagex/bash . /
COPY --from=make . /
COPY --from=musl . /
COPY --from=zlib . /
COPY --from=git . /
COPY --from=openssl . /
COPY --from=libunwind . /
COPY --from=coreutils . /
COPY --from=eif_build . /
COPY --from=gcc . /
COPY --from=bootstrap /build/out .
COPY --from=ca-certificates /etc/ssl/certs /etc/ssl/certs

FROM stagex/pallet-go AS build_go
ARG APP_NAME
COPY --from=base . /

ENV CGO_ENABLED=0

WORKDIR /build
COPY . ./

RUN make build
RUN cp bin/${APP_NAME} bin/enclave
RUN go install github.com/linuxkit/linuxkit/src/cmd/linuxkit@270fd1c5aa1986977b31af6c743c6a2681f67a29
RUN linuxkit build --format kernel+initrd --no-sbom --name init-ramdisk ./docker/app/eif/init-ramdisk.yaml
RUN linuxkit build --format kernel+initrd --no-sbom --name user-ramdisk ./docker/app/eif/user-ramdisk.yaml

FROM base AS build_eif
SHELL ["/bin/bash", "-c"]
COPY docker/app/eif/cmdline-x86_64 cmdline
COPY --from=build_go /build/init-ramdisk-initrd.img .
COPY --from=build_go /build/user-ramdisk-initrd.img .

RUN eif_build \
    --kernel /bzImage \
    --kernel_config /bzImage.config \
    --cmdline "$(cat cmdline)" \
    --ramdisk init-ramdisk-initrd.img \
    --ramdisk user-ramdisk-initrd.img \
    --pcrs_output /nitro.pcrs \
	--output /nitro.eif


FROM dimozone/nitro-enclave-builder:latest

ARG APP_NAME
COPY --from=build_eif /nitro.eif /${APP_NAME}.eif
COPY --from=build_eif /nitro.pcrs /${APP_NAME}.pcrs
COPY --from=build_go /build/bin/${APP_NAME} /bin/enclave
COPY ./docker/enclave-runner/run.sh /run.sh
RUN chmod +x /run.sh


ENV APP_NAME=${APP_NAME}
CMD ["/run.sh", "start"]
