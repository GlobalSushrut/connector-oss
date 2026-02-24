"""connector_oss — Tamper-proof memory and chain-of-custody for AI agents.

Install:
    pip install connector_oss

Usage:
    import os
    from connector_oss import Connector

    c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
    result = c.agent("bot", "You are helpful.").run("Hello!", "user:alice")

    print(result.text)         # LLM response
    print(result.trust)        # 0-100 kernel-verified trust score
    print(result.trust_grade)  # "A+" | "A" | "B" | "C" | "D" | "F"
    print(result.cid)          # tamper-proof CID of this response
    print(result.verified)     # True if all events are kernel-verified
"""

try:
    from vac_ffi import Connector, AgentHandle, PipelineOutput
except ImportError:
    raise ImportError(
        "\n"
        "connector_oss requires the native Rust kernel (vac_ffi).\n"
        "\n"
        "If you installed via pip, the wheel should have included it.\n"
        "If you are building from source:\n"
        "\n"
        "  cd vac/crates/vac-ffi\n"
        "  maturin develop --release\n"
        "\n"
        "Then re-install:\n"
        "  cd sdks/python && pip install -e .\n"
    )

__all__ = ["Connector", "AgentHandle", "PipelineOutput"]
__version__ = "0.1.0"
__author__ = "Connector OSS Contributors"
__license__ = "Apache-2.0"
