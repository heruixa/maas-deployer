from setuptools import setup, find_packages

setup(
    name="maas-deployer",
    version="0.0.1",
    description="A tool for deploying MAAS clusters using virtual machines.",
    long_description=open("README").read(),
    author="Billy Olsen",
    author_email="billy.olsen@gmail.com",
    url="https://launchpad.net/maas-deployer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers"],
    test_suite="maas_deployer.vmaas.tests",
    entry_points={
        "console_scripts": [
            'maas-deployer = maas_deployer.cli:main']})
