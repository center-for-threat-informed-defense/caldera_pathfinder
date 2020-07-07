def init(vals):
    for k, v in vals.items():
        globals()[k] = v
