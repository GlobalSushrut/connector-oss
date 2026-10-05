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
    from connector_oss.vac_ffi import Connector, Agent, Pipeline, PipelineResult
except ImportError:
    try:
        from vac_ffi import Connector, Agent, Pipeline, PipelineResult  # type: ignore
    except ImportError:
        raise ImportError(
            "\n"
            "connector_oss requires the native Rust kernel.\n"
            "\n"
            "If you installed via pip and see this, please report a bug.\n"
            "To build from source:\n"
            "\n"
            "  cd sdks/python\n"
            "  maturin develop --release\n"
        )

__all__ = ["Connector", "Agent", "Pipeline", "PipelineResult"]
__version__ = "0.1.0"
__author__ = "Connector OSS Contributors"
__license__ = "Apache-2.0"
