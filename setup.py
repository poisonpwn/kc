from setuptools import find_packages, setup

setup(
    name="kc",
    author="Adithyadev Rajesh",
    version="1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
)
