from pathlib import Path


class TestRepydaData(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_get_data(self):
        data = repyda.Data(0x18014cfff)
        assert data.ea == 0x18014cfff

        assert repyda.Data(data.ea + 1).ea == 0x18014cfff

    def test_name(self):
        data = repyda.Data(0x18014cfff)
        assert data.name == 'aRtlcapturestac'
        assert data.is_auto_name
        assert not data.is_user_defined_name

        data.name = 'hello'
        assert data.name == 'hello'
        assert not data.is_auto_name
        assert data.is_user_defined_name

        del data.name
        assert not data.is_user_defined_name

    def test_sequence(self):
        data = repyda.Data(0x18014cfff)
        assert data.next.name == 'aRtlchartointeg'
        assert data.prev.name == 'aRtlcapturecont'

    def test_iterable(self):
        import pytest
        pytest.skip('This is broken, need to fix iter, it returns different sizes and data')

        all_data = list(repyda.Data.iter())
        assert len(all_data) == 0x9e1a

        assert all_data[50].name == 'byte_180048BFD'
        assert all_data[400].name == 'byte_1800CAC7E'

    def test_type(self):
        pass

    def test_value(self):
        pass

    def test_references(self):
        pass