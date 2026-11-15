#!/bin/bash -eu
# ClusterFuzzLite build script: packs every fuzz/fuzz_*.py target with PyInstaller into $OUT (compile_python_fuzzer
# from the OSS-Fuzz Python base image) and adds its seed corpus from fuzz/corpus/<target>/.
#
# Python 3.12 and all dependencies come from uv.lock (hash-checked): the runtime dependencies of the project plus the
# "fuzz" group (atheris, PyInstaller). The PyInstaller bundle contains its own interpreter, so the fuzzers do not
# depend on the image's Python 3.11 at run time.

export UV_PROJECT_ENVIRONMENT=/opt/fuzz-venv
export UV_PYTHON_INSTALL_DIR=/opt/uv-python
export UV_LINK_MODE=copy
export UV_NO_CACHE=1
uv sync --frozen --no-dev --group fuzz --no-editable --python 3.12
export PATH="/opt/fuzz-venv/bin:$PATH"

for fuzzer in fuzz/fuzz_*.py; do
  name="$(basename -s .py "$fuzzer")"
  compile_python_fuzzer "$fuzzer" --paths fuzz
  if [[ -d "fuzz/corpus/$name" ]]; then
    (cd "fuzz/corpus/$name" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
  fi
done
