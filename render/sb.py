import angr
import networkx as nx

from ptrlib                                    import ELF
from loguru                                    import logger
from pprint                                    import pprint
from angr.knowledge_plugins.functions.function import Function
from cle.backends.elf.symbol                   import ELFSymbol

import matplotlib.pyplot as plt
import angrutils
from angr.analyses.decompiler.utils import to_ail_supergraph

# cfg fast没考虑上下文关系 而cfg emulated考虑了
# CFGFast是通过静态分析获得CFG，CFGEmulated是通过动态符号执行获得更加准确的CFG
def render_cfg(proj: angr.Project, funcsym: str, outfilename: str="test.cfg") -> None:
    '''
    render a cfg png picture
    '''
    fnsym: ELFSymbol = proj.loader.main_object.get_symbol(funcsym)
    start_state = proj.factory.blank_state(addr=fnsym.rebased_addr)
    cfgemu: angr.analyses.CFGEmulated = proj.analyses.CFGEmulated(
        fail_fast=True,
        starts=[fnsym.rebased_addr], 
        initial_state=start_state
    )
    angrutils.plot_cfg(
        cfgemu, 
        outfilename, 
        asminst=True, 
        remove_imports=True, 
        remove_path_terminator=True
    )  
    logger.info("cfg render successfully")

def main():
    filename = "./bin/test"
    proj = angr.Project(filename, load_options={
        "auto_load_libs" : False
    })

    # render_cfg(proj, "test", "test.cfg")

    cfgfast: angr.analyses.CFGFast = proj.analyses.CFGFast(
        normalize=True, force_complete_scan=False
    )

    test_sym: ELFSymbol = proj.loader.main_object.get_symbol("test")
    test_fn: Function = cfgfast.functions.get(test_sym.rebased_addr)
    # breakpoint()
    # test_graph: networkx.DiGraph = 
    # logger.debug(test_fn.transition_graph)
    # test_fn.transition_graph.render('graph', format='png')

    # 渲染 Digraph
    angrutils.plot_common(test_fn.transition_graph, "before-modify.cfg")



main()












