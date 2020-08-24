import abc


class ParserInterface(abc.ABC):
    @abc.abstractmethod
    def parse(self, report):
        pass
