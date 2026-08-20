"""Extract the 16 kHz branch parameters from the canonical Silero VAD v5 ONNX release.

Out-of-tree tool: it runs once, on this machine, and emits a flat little-endian f32
blob that the Rust crate embeds with include_bytes!.  Nothing here is part of the
siphon-rtp build.
"""

import hashlib
import struct
import sys

import numpy as np
import onnx
from onnx import numpy_helper

# Order matters: it is the on-disk layout the Rust side reads back by offset.
LAYOUT = [
    ("stft.forward_basis_buffer", (258, 1, 256)),
    ("encoder.0.reparam_conv.weight", (128, 129, 3)),
    ("encoder.0.reparam_conv.bias", (128,)),
    ("encoder.1.reparam_conv.weight", (64, 128, 3)),
    ("encoder.1.reparam_conv.bias", (64,)),
    ("encoder.2.reparam_conv.weight", (64, 64, 3)),
    ("encoder.2.reparam_conv.bias", (64,)),
    ("encoder.3.reparam_conv.weight", (128, 64, 3)),
    ("encoder.3.reparam_conv.bias", (128,)),
    ("decoder.rnn.weight_ih", (512, 128)),
    ("decoder.rnn.weight_hh", (512, 128)),
    ("decoder.rnn.bias_ih", (512,)),
    ("decoder.rnn.bias_hh", (512,)),
    ("decoder.decoder.2.weight", (1, 128, 1)),
    ("decoder.decoder.2.bias", (1,)),
]


def load_branch_constants(path, sixteen_khz=True):
    model = onnx.load(path)
    branch_name = "then_branch" if sixteen_khz else "else_branch"
    branch = None
    for node in model.graph.node:
        if node.op_type == "If":
            for attribute in node.attribute:
                if attribute.name == branch_name:
                    branch = attribute.g
    assert branch is not None
    out = {}
    for node in branch.node:
        if node.op_type == "Constant":
            for attribute in node.attribute:
                if attribute.name == "value":
                    out[node.output[0].split("__Inline_0__")[-1]] = numpy_helper.to_array(attribute.t)
    return out


def main():
    onnx_path = sys.argv[1]
    blob_path = sys.argv[2]
    with open(onnx_path, "rb") as handle:
        source_hash = hashlib.sha256(handle.read()).hexdigest()

    constants = load_branch_constants(onnx_path)
    payload = bytearray()
    offset = 0
    print(f"source: {onnx_path}")
    print(f"sha256: {source_hash}")
    for name, shape in LAYOUT:
        tensor = constants[name]
        assert tensor.shape == shape, (name, tensor.shape, shape)
        assert tensor.dtype == np.float32, (name, tensor.dtype)
        flat = np.ascontiguousarray(tensor, dtype="<f4")
        payload += flat.tobytes()
        print(f"  {name:34s} {str(shape):16s} offset={offset:7d} count={flat.size}")
        offset += flat.size
    print(f"total f32 values: {offset}  bytes: {len(payload)}")

    with open(blob_path, "wb") as handle:
        handle.write(payload)
    print("blob sha256:", hashlib.sha256(bytes(payload)).hexdigest())


if __name__ == "__main__":
    main()
