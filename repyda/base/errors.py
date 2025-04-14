
class RepydaError(Exception):
    pass


class RepydaDecompileError(RepydaError):
    """
        :class:`RepydaError` for decompilation failure. Main reason for this
        is that hexrays failed to decompile a function or that the address
        provided was not inside a function.
    """
    pass
