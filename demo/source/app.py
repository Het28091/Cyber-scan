# Synthetic source only. Never executed by the scanner.
import subprocess
DEBUG = True
password = "synthetic-only-not-a-credential"
def unsafe_example(user_input):
    return eval(user_input)
def shell_example(user_input):
    return subprocess.run(user_input, shell=True)
