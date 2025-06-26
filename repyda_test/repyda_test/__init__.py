from pathlib import Path
import pytest


class IDBTestCase:
    IDB: Path
    AUTO_ANALISYS: bool = True
    MODIFY_IDB: bool = False
    
    @pytest.fixture(autouse=True, scope='class')
    def idb(self):
        import ida
        ida.open_database(str(self.IDB), self.AUTO_ANALISYS)
        yield
        ida.close_database(self.MODIFY_IDB)
