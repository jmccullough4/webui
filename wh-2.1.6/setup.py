from setuptools import setup

version_globals = {}
with open("./wh/version.py") as f:
    exec(f.read(), version_globals)

# Read the dependencies from requirements.txt
with open("./wh/requirements.txt") as f:
    dependencies = f.read().splitlines()

setup(
    name='wh',
    version=version_globals['__version__'],
    author='CTG',
    author_email='',
    description='CTG Warhammer Node Backend',
    packages=['wh'],
    package_data={
        'wh': [
          'app.py',
          'license_manager.py',
          'requirements.txt',
          'version.py',
          'frontend_build/**',
          'config/**',
          'utils/**',
          'routes/**',
          'scripts/**',
          'tests/**',
          'readmes/**',
          'issuer_keys/**'
        ],
        '': [
          'run_app.py'
        ]
    },
    install_requires=dependencies,
    exclude_package_data={
        '': [
            '*.pyc',
            '__pycache__',
            'env.sh'
        ]
    }
)