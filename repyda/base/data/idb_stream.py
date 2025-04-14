from typing import Optional
import io

import ida_kernwin
import ida_bytes


class IDBStream(io.IOBase):
    def __init__(self,
                 ea: Optional[int] = None,
                 *,
                 max_allowed_read: Optional[int] = 0x1000):
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        self._ea = ea
        self._pos = 0
        self._max_allowed_read = max_allowed_read

    def tell(self) -> int:
        return self._pos

    def rewind(self):
        self._pos = 0

    def readable(self) -> bool:
        return True

    def read(self, size=-1) -> bytes:
        if size == -1:
            size = self._max_allowed_read

        data = ida_bytes.get_bytes(self._ea + self._pos, size, ida_bytes.GMB_READALL)
        self._pos += len(data)
        return data