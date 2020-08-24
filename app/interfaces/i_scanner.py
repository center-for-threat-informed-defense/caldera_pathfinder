import abc


class ScannerInterface(abc.ABC):
    @abc.abstractmethod
    def scan(self):
        pass
