from vpp_object import VppObject


class VppApiTrace(VppObject):
    """VPP API trace class"""

    def __init__(self, test, filename="trace.api"):
        """Init"""
        self._test = test
        self._filename = filename

    def add_vpp_config(self):
        """Configure API trace"""
        self._test.vapi.api_trace_enable_disable()

    def remove_vpp_config(self):
        """Remove api trace"""
        self._test.vapi.api_trace_free()

    @property
    def _status(self):
        return self._test.vapi.api_trace_status()

    @property
    def filename(self):
        """Return API trace filename"""
        return self._filename

    @filename.setter
    def filename(self, filename):
        """Set api trace filename"""
        self._filename = filename

    @property
    def enabled(self):
        """Return api trace status"""
        return self._status.enabled

    @property
    def traces(self):
        """Return number of traces"""
        return self._status.traces

    def save(self):
        """Save api trace to a file"""
        return self._test.vapi.api_trace_save(filename=self.filename)

    def replay(self, first_index=0, last_index=0xFFFFFFFF):
        """Replay api trace from file"""
        return self._test.vapi.api_trace_replay(first_index=first_index,
                                                last_index=last_index,
                                                filename=self.filename)

    def query_vpp_config(self):
        """Query api trace config"""
        return self.enabled
