# fuzz_example.py
import atheris
import sys

@atheris.instrument_func
def check_permission(permission: str) -> bool:
    if permission == 'fuzzing_is_available':
        return False
    elif permission == 'fuzzing_is_not_available':
        return True
    elif permission == 'check_permission':
        return True
    return True

@atheris.instrument_func
def do_calc(permission: str) -> int:
    is_available = check_permission(permission)
    if is_available:
        return 2 + 2
    else:
        return -1

def run_fuzzing(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # create a short string from fuzzed bytes (no surrogates)
    s = fdp.ConsumeUnicodeNoSurrogates(50)
    # call the functions under test
    try:
        _ = check_permission(s)
        _ = do_calc(s)
    except Exception:
        # let the fuzzer capture any unexpected exceptions
        raise

def main():
    atheris.Setup(sys.argv, run_fuzzing)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
