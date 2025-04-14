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