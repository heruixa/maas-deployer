from setuptools import setup, find_packages

setup(
    name="maas-deployer",
    version="0.0.7",
    description="A tool for deploying MAAS clusters using virtual machines.",
    long_description=open("README.md").read(),
    author="MAAS Deployers",
    author_email="maas-deployers@lists.launchpad.net",
    url="https://launchpad.net/maas-deployer",
    packages=find_packages(),
    package_data={'maas_deployer': ['vmaas/templates/*']},
    data_files=[('/usr/share/maas-deployer/examples',
                 ['examples/deployment.yaml'])],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers"],
    test_suite="maas_deployer.vmaas.tests",
    entry_points={
        "console_scripts": [
            'maas-deployer = maas_deployer.cli:main']})
