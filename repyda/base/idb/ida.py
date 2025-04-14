import ida_kernwin
import idaapi


class IDA:
    """
        Class for regrouping interfaces with IDA in itself. This can include
        configurations and thing specific to the IDA API.

        Currently this contain only static methods.
    """

    @staticmethod
    def exec_sync(func, *args, **kwargs):
        """
        Call function on IDA's main thread. Functions that aren't marked thread
        safe need to use this API.
        """
        MFF_FLAG = kwargs.get("MFF_FLAG", ida_kernwin.MFF_READ)

        ret = {
            "ret": None,
            "exception": None,
        }

        def handle():
            try:
                ret["ret"] = func(*args, **kwargs)
            except Exception as ex:
                ret["exception"] = ex
            finally:
                return 1

        ida_kernwin.execute_sync(handle, MFF_FLAG)

        if ret["exception"] is not None:
            raise ret["exception"] from None

        return ret["ret"]

    @staticmethod
    def exit_no_save_idb():
        '''
        Pack IDB, don't save changes and exit IDA.
        '''
        IDA.exec_sync(idaapi.process_config_directive, ('ABANDON_DATABASE=YES',))
        IDA.exec_sync(idaapi.qexit, (0,))