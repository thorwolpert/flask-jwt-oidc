from setuptools import setup

import os

def is_package(path):
    return (
        os.path.isdir(path) and
        os.path.isfile(os.path.join(path, '__init__.py'))
        )

def find_packages(path, base="" ):
    """ Find all packages in path """
    packages = {}
    for item in os.listdir(path):
        dir = os.path.join(path, item)
        if is_package( dir ):
            if base:
                module_name = "%(base)s.%(item)s" % vars()
            else:
                module_name = item
            packages[module_name] = dir
            packages.update(find_packages(dir, module_name))
    return packages

def read_requirements(filename):
    """
    Get application requirements from
    the requirements.txt file.
    :return: Python requirements
    :rtype: list
    """
    with open(filename, 'r') as req:
        requirements = req.readlines()
    install_requires = [r.strip() for r in requirements if r.find('git+') != 0]
    return install_requires


def read(filepath):
    """
    Read the contents from a file.
    :param str filepath: path to the file to be read
    :return: file contents
    :rtype: str
    """
    with open(filepath, 'r') as f:
        content = f.read()
    return content


requirements = read_requirements('requirements/prod.txt')

packages = find_packages(".")


setup(name='flask_jwt_oidc',
      version='0.1.3',
      description='Flask JWT OIDC',
      author='thor wolpert, with help from others',
      author_email='thor@wolpert.ca',
      url='https://github.com/thorwolpert/flask-jwt-oidc',
      license=read('LICENSE'),
      include_package_data=False,
      long_description =read('README.md'),
      packages=packages.keys(),
      package_dir=packages,
      install_requires=requirements,
      setup_requires=[
          'pytest-runner',
      ],
      tests_require=[
           'pytest',
      ],
      platforms='any',
      zip_safe=False,
      keywords='flask extension development',
      classifiers = [
           'Development Status :: 0.1.3 - Beta',
           'Environment :: Web API',
           'Intended Audience :: Developers',
           'License :: OSI Approved :: Apache 2.0 License',
           'Operating System :: MacOS :: MacOS X',
           'Operating System :: Microsoft :: Windows',
           'Operating System :: POSIX',
           'Programming Language :: Python',
           'Topic :: Communications :: Email',
           'Topic :: Software Development :: GitHub Issue Tracking',
           'Topic :: Software Development :: Libraries :: Python Modules'
      ],
)
