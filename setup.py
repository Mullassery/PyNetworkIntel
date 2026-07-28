from setuptools import setup, find_packages

setup(
    name="pynetworkintel",
    version="0.2.0",
    description="AI-powered network intelligence and vulnerability discovery platform",
    author="Georgi Mullassery",
    author_email="mullassery@gmail.com",
    url="https://github.com/Mullassery/PyNetworkIntel",
    project_urls={
        "Documentation": "https://github.com/Mullassery/PyNetworkIntel",
        "Source Code": "https://github.com/Mullassery/PyNetworkIntel",
        "Bug Tracker": "https://github.com/Mullassery/PyNetworkIntel/issues",
    },
    packages=find_packages(),
    package_data={
        "pynetworkintel": ["py.typed"],
    },
    python_requires=">=3.10",
    install_requires=[
        "paramiko>=3.0",
        "netaddr>=0.9",
        "pyyaml>=6.0",
        "requests>=2.31",
        "anthropic>=0.25",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4",
            "pytest-cov>=4.1",
            "black>=23.7",
            "ruff>=0.0.280",
        ],
    },
    entry_points={
        "console_scripts": [
            "pynetworkintel=pynetworkintel.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
