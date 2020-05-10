#! /usr/bin/env python

try:
    from setuptools import setup, find_packages
except:
    raise ImportError("setuptools is required to install!")
import io
import os


def get_long_description():
    """Extract description from README.md, for PyPI's usage"""

    def process_ignore_tags(buffer):
        return "\n".join(
            x for x in buffer.split("\n") if "<!-- ignore_ppi -->" not in x
        )

    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            return process_ignore_tags(readme.strip())
    except IOError:
        return None


# https://packaging.python.org/guides/distributing-packages-using-setuptools/
setup(
    name="mca-traceroute",
    version=__import__("mca").VERSION,
    packages=["mca"],
    entry_points={"console_scripts": ["mca-traceroute = mca.__main__:main"]},
    python_requires=">=3.6, < 4",
    install_requires=["scapy"],
    zip_safe=False,
    # Metadata
    author="Rafael Almeida",
    author_email="rlca@dcc.ufmg.br",
    maintainer="Ítalo Cunha",
    description="mca-traceroute: Detection and Classification of Load Balancers",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    license="GPLv3",
    url="https://www.dcc.ufmg.br/~rlca/mca",
    project_urls={"Source Code": "https://github.com/rlcalmeida/mca"},
    keywords=["network"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
