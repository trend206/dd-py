from setuptools import setup

setup(name='dd-py',
      version='0.1c',
      description='Python 3 client for Trend Micro\'s Deep Discovery Platform',
      url='https://github.com/trend206/dd-py',
      author='Jeff Thorne',
      author_email='jthorne@u.washington.edu',
      license='MIT',
      packages=['ddpy', 'ddpy.interfaces', 'ddpy.utils'],
      install_requires=['requests >= 2.9.1'],
      zip_safe=False)