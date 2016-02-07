""" 
Pygments stuff for my mastersthesis
""" 
from setuptools import setup, find_packages

setup( 
    name         = 'pygments-mastersthesis',
    version      = '1.0',
    description  = __doc__,
    author       = "Sven Hueser",
    install_requires = ['pygments'],
    packages     = find_packages(),
    entry_points = '''
    [pygments.styles]
    mastersthesis = pygments_mastersthesis.style:MastersthesisStyle
    [pygments.lexers]
    currylexer = pygments_mastersthesis.lexers:CurryLexer
    smt2lexer  = pygments_mastersthesis.lexers:Smt2Lexer
    picatlexer = pygments_mastersthesis.lexers:PicatLexer
    '''
)
