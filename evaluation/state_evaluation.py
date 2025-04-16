import angr

def total_basic_block(binary, lib):
    if lib:
        angr_proj = angr.Project(binary, ld_path=lib, auto_load_libs=False)
    else:
        angr_proj = angr.Project(binary, auto_load_libs=False)
    cfg = angr_proj.analyses.CFGEmulated()
    print('total number of bbl:')
    num = cfg.basic_blocks
    return


if __name__ == "__main__":
    binary_path = '/home/qybpt/Desktop/libmodbus-3.1.10/tests/.libs/unit-test-server'
    library = '/home/qybpt/Desktop/libmodbus-3.1.10/src/.libs/'
    total_basic_block(binary_path, library)
