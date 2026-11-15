# ClusterFuzzLite build image for the atheris fuzz targets in fuzz/ (see .clusterfuzzlite/build.sh).
# Base images are pinned by digest (Dependabot keeps them current). The OSS-Fuzz Python base ships Python 3.11, the
# project needs >= 3.12 – build.sh therefore installs Python 3.12 and the locked dependencies (incl. atheris and
# PyInstaller from the "fuzz" group, with hashes from uv.lock) with uv.
FROM ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY --from=uv /uv /usr/local/bin/uv
COPY . $SRC/fritzos8-mcp
WORKDIR $SRC/fritzos8-mcp
COPY .clusterfuzzlite/build.sh $SRC/
