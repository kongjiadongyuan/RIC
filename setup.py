from setuptools import setup, find_packages

setup(
    name="ric",
    packages=find_packages(),
    version="0.0.1",
    install_requires=[
        "rpyc",
    ],
    description="Remote IDA Call, a tool to call IDA functions remotely",
    author="kjdy",
    author_email="zhaggbl@foxmail.com",
)