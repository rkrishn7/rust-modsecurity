#!/usr/bin/env bash

bindgen \
    --no-doc-comments \
    --no-layout-tests \
    --rustified-enum ".*" \
    --allowlist-function "msc.*" \
    --allowlist-type "ModSec.*" \
    --allowlist-type "Transaction_t" \
    --allowlist-type "Rules_t" \
    "wrapper.h" -o "src/bindings.rs"
