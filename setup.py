from setuptools import setup, find_packages
from setuptools.command.install import install
from pathlib import Path
from importlib.util import find_spec
import sys
import os
import re
import subprocess
import shutil


IPYIDARC = '''
from idapythonrc import reload_package
'''

IDAPYTHONRC = '''
def reload_package(package: str, recurse: bool = True):
    """
    Reload a previous loaded package. This will execute top level code in the package.

    This function is intended for plugin and package development. It is useful to
    reload a package that you have updated using setup.py or any other method without
    restarting IDA.

    Note that even after executing this function, you will need to use the import
    statement again to get the new version of the module. If you have used the from
    ... import ... syntax you will have to use del to remove the previously imported
    name and use the same syntax again. This only applies to the top level of the
    interpreter (if a function calls from ... import ...) the namespace is created
    again when the function is run so everything will work with the new version of
    the module.

    :param pacakge: The name of the package
    :param recurse: Whether to also reload submodules. This will cause top level
                    code to be executed in the submodules as well. Defaults to True.
    """
    import importlib
    import sys

    if not recurse:
        module = sys.modules[package]
        importlib.reload(module)

    for name, module in sys.modules.copy().items():
        if package not in name:
            continue

        try:
            importlib.reload(module)
        except ModuleNotFoundError:
            # This happens if we loaded a module under the IDA plugins directory
            pass
'''


class InstallRepydaPluginManager(install):
    def _get_ida_folder(self):
        if os.getenv('IDAUSR') is not None:
            return Path(os.getenv('IDAUSR'))
        elif sys.platform in ("linux", "linux2", "darwin"):
            return Path(os.getenv('HOME')) / '.idapro'
        elif sys.platform == "win32":
            return Path(os.getenv('APPDATA')) / 'Hex-Rays' / 'IDA Pro'

        raise RuntimeError('Unknwown OS do not know where to install')

    def _wrap_rcfile_content(self, rcfile_content: str) -> str:
        head = '# --- repyda start ---'
        tail = '# --- repyda end ---'
        return f'{head}\n{rcfile_content}\n{tail}'

    def _update_rcfile(self, source_data: str, destination: Path):
        if not destination.exists():
            with open(destination, 'w') as destination_rcfile:
                destination_rcfile.write(self._wrap_rcfile_content(source_data))
                destination_rcfile.write('\n')

            print(f'[+] Created {destination}')
            return

        with open(destination, 'r') as destination_rcfile:
            destination_data = destination_rcfile.read()

        head = '# --- repyda start ---'
        tail = '# --- repyda end ---'
        updated = re.sub(f'{head}(.*){tail}',
                         f'{head}\n{source_data}\n{tail}',
                         destination_data,
                         flags=re.DOTALL)

        if head not in updated:
            updated += f'\n{head}\n{source_data}\n{tail}'

        with open(destination, 'w') as destination_rcfile:
            destination_rcfile.write(updated)

        print(f'[+] Updated {destination}')

    def _setup_idapythonrc(self):
        print('[+] Setting up idapythonrc.py')
        idapythonrc_path = self._get_ida_folder() / 'idapythonrc.py'
        ipyidarc_path = self._get_ida_folder() / 'ipyidarc.py'

        self._update_rcfile(IDAPYTHONRC, idapythonrc_path)
        self._update_rcfile(IPYIDARC, ipyidarc_path)

    def _install_ida_lib(self):
        ida_lib_name = 'ida'
        
        if (spec := find_spec(ida_lib_name)) is not None:
            print(f'[+] idalib installed at {spec.origin}')
            return
        
        ida_64 = shutil.which('ida64.exe')
        if ida_64 is None:
            print('[!] Failed to find ida installation directory, some features will not be available')
            print('[?] Look into your ida install directory, under idalib and follow the readme for manual installation')
            return
        
        ida_lib_python = Path(ida_64).parent / 'idalib' / 'python'
        if 0 != subprocess.check_call([sys.executable, "-m", "pip", "install", str(ida_lib_python)]):
            print(f'[!] Failed to install idalib, some features will not be available')
            print('[?] Look into your ida install directory, under idalib and follow the readme for manual installation')
            return
        
        actiavte_idalib_script = ida_lib_python / 'py-activate-idalib.py'
        if 0 != subprocess.check_call([sys.executable, str(actiavte_idalib_script)]):
            print('[!] Failed to activate idalib, some features will not be available')
            print('[?] This is most likely due to insufficient privileges, run the activate script as admin/root')
            print('[?] Look into your ida install directory, under idalib and follow the readme for manual installation')
            return

        print('[+] Successfuly installed idalib')

    def run(self):
        install.run(self)
        self._setup_idapythonrc()
        self._install_ida_lib()

setup(
    name='repyda',
    version='1.0.0',
    packages=find_packages(include=['repyda', 'repyda.*']),
    author='Omri Levy',
    author_email='omrilevy888@gmail.com',
    description='IDA Python API wrapper',
    cmdclass={
        'install': InstallRepydaPluginManager
    },
    install_requires=['construct', 'sphinx', 'sphinx_rtd_theme'],
)