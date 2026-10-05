from setuptools import setup, find_packages

setup(
    name="connector-sdk",
    version="0.1.0",
    description="Python SDK and Gloo developer layer for the Connector Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Connector Platform",
    url="https://github.com/connector-platform/connector",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "async": ["httpx>=0.24.0"],
        "typed": ["pydantic>=2.0"],
        "langchain": ["langchain-core>=0.1.0", "requests>=2.28.0"],
        "autogen": ["pyautogen>=0.4.0", "requests>=2.28.0"],
        "crewai": ["crewai>=0.1.0", "requests>=2.28.0"],
        "llamaindex": ["llama-index-core>=0.10.0", "requests>=2.28.0"],
        "dspy": ["dspy-ai>=2.0.0", "requests>=2.28.0"],
        "haystack": ["haystack-ai>=2.0.0", "requests>=2.28.0"],
        "all": [
            "httpx>=0.24.0", "pydantic>=2.0",
            "langchain-core>=0.1.0", "pyautogen>=0.4.0",
            "crewai>=0.1.0", "llama-index-core>=0.10.0",
            "dspy-ai>=2.0.0", "haystack-ai>=2.0.0",
        ],
        "dev": ["pytest>=7.0", "pytest-mock>=3.0"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="ai agent memory mcp a2a compliance hallucination safety",
    project_urls={
        "Documentation": "https://connector.dev/docs",
        "Source": "https://github.com/connector-platform/connector",
        "Tracker": "https://github.com/connector-platform/connector/issues",
    },
    entry_points={
        "console_scripts": [
            "gloo=connector_sdk.gloo.cli:main",
        ]
    },
)
