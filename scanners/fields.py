class TextField:
    def __init__(self, param, label=None, default=None):
        self.type = 'text'
        self.param = param
        self.name = label or param
        self.default = default or ''


class PulldownField:
    def __init__(self, param, values, label=None, prompt=None, default=None):
        self.type = 'pulldown'
        self.param = param
        self.name = label or param
        self.values = values
        self.prompt = prompt
        self.default = values[0] if default is None else default


class CheckboxField:
    def __init__(self, param, label=None, default=None):
        self.type = 'checkbox'
        self.param = param
        self.name = label or param
        self.default = False if default is None else default
