# setup.py

from setuptools import setup, find_packages

setup(
    name="stackaudit",
    version="1.0.0",
    description="AWS Misconfiguration Scanner",
    author="Taaha",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "pandas",
        "fpdf",
        "XlsxWriter"
    ],
    entry_points={
        "console_scripts": [
            "stackaudit=stackaudit.cli:main"
        ]
    },
    include_package_data=True,
)
