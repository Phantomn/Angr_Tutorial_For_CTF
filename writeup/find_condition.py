import angr

def main():
    # create project
    proj = angr.Project('../problems/02_angr_find_condition')
    # entry point
    init_state = proj.factory.entry_state()
    # create simulation
    simulation = proj.factory.simgr(init_state)
    # expected address
    print_good = 0x80486718
    print_bad = 0x8048678
    # start explore
    simulation.explore(find=print_good, avoid=print_bad)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(0))
    else:
        print('no solution')

if __name__ == '__main__':
    main()
    


