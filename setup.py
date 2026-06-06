from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kavach-mcp",
    version="0.1.11",
    description="Security middleware for Model Context Protocol (MCP) that detects and blocks malicious tool calls",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Shivam Namdeo",
    author_email="shivamnamdeo0101@gmail.com",
    url="https://github.com/shivamnamdeo0101/kavach-mcp-middleware",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "fastmcp>=0.1.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
    ],
    keywords="mcp security middleware detection",
)
