from setuptools import setup, find_packages

setup(
    name="signverify",
    version="1.0.0",
    url="https://github.com/PiRK/signverify",
    author="PiRK",
    description="Desktop GUI application to sign and verify a message using"
    " bitcoin private/public keys",
    packages=find_packages(),
    install_requires=["PySide2", "ecdsa", "ElectrumABC"],
    entry_points={"gui_scripts": ["signverify = signverify.__main__:main"]},
)
