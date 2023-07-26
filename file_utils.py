import os


def is_file(filename):
    return os.path.isfile(filename)


def read_file(filename):
    with open(filename, 'rb') as f:
        return f.read()


def save_file(filename, content):
    with open(filename, 'wb') as f:
        f.write(content)
