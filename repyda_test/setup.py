from setuptools import setup, find_packages

setup(
    name='repyda_test',
    version='1.0.0',
    packages=find_packages(include=['repyda_test', 'repyda_test.*']),
    author='Omri Levy',
    author_email='omrilevy888@gmail.com',
    description='IDA pytest integration',
)