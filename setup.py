from setuptools import setup, find_packages
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

setup(
    name="satfs",
    version="0.1",
    author="Jérémy Ruffet",
    author_email="sat@airnux.fr",
    description="FUSE-based access control layer to protect a directory and its subtree",
    long_description=(BASE_DIR / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        line.strip()
        for line in (BASE_DIR / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ],
    entry_points={"console_scripts": ["satfs = main:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.12",
)
