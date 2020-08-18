class TextField:
    def __init__(self, param, label=None, default=None):
        self.type = 'text'
        self.param = param
        self.name = label or param
        self.default = default or ''


class PulldownField:
    def __init__(self, param, values, label=None, prompt=None):
        self.type = 'pulldown'
        self.param = param
        self.name = label or param
        self.values = values
        self.prompt = prompt


class CheckboxField:
    def __init__(self, param, label=None):
        self.type = 'checkbox'
        self.param = param
        self.name = label or param
