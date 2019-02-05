# -*- coding: utf-8 -*-
"""
    pygments.lexers.mastersthesis
    ~~~~~~~~~~~~~~~~~~~~~~~

    Lexers for Curry, SMT2 and Picat.
"""

import re

from pygments.lexer import Lexer, RegexLexer, bygroups, do_insertions, \
    default, include
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation, Generic
from pygments import unistring as uni

__all__ = ['CurryLexer']


line_re = re.compile('.*?\n')


class CurryLexer(RegexLexer):
    """
    A Curry lexer based off the Haskell lexer.
    """
    name = 'Curry'
    aliases = ['curry']
    filenames = ['*.curry']
    mimetypes = ['text/x-curry']

    flags = re.MULTILINE | re.UNICODE

    reserved = ('case', 'class', 'data', 'deriving', 'do', 'else',
                'if', 'in', 'infix[lr]?', 'instance', 'when', 'unless',
                'let', 'newtype', 'of', 'then', 'type', 'where', 'free')
    ascii = ('NUL', 'SOH', '[SE]TX', 'EOT', 'ENQ', 'ACK',
             'BEL', 'BS', 'HT', 'LF', 'VT', 'FF', 'CR', 'S[OI]', 'DLE',
             'DC[1-4]', 'NAK', 'SYN', 'ETB', 'CAN',
             'EM', 'SUB', 'ESC', '[FGRU]S', 'SP', 'DEL')

    tokens = {
        'root': [
            # Whitespace:
            (r'\s+', Text),
            # (r'--\s*|.*$', Comment.Doc),
            (r'--(?![!#$%&*+./<=>?@^|_~:\\]).*?$', Comment.Single),
            (r'\{-', Comment.Multiline, 'comment'),
            # Lexemes:
            #  Identifiers
            (r'\bimport\b', Comment.Preproc, 'import'),
            (r'\bmodule\b', Keyword.Reserved, 'module'),
            (r'\berror\b', Name.Exception),
            (r'\b(%s)(?!\')\b' % '|'.join(reserved), Keyword.Reserved),
            (r"'[^\\]'", String.Char),  # this has to come before the TH quote
            (r'^[_' + uni.Ll + r'][\w\']*', Name.Function),
            (r"'?[_" + uni.Ll + r"][\w']*", Name),
            (r"('')?[" + uni.Lu + r"][\w\']*", Keyword.Type),
            #  Operators
            (r'\\(?![:!#$%&*+.\\/<=>?@^|~-]+)', Name.Function),  # lambda operator
            (r'(<-|::|->|=>|=)(?![:!#$%&*+.\\/<=>?@^|~-]+)', Operator.Word),  # specials
            (r':[:!#$%&*+.\\/<=>?@^|~-]*', Keyword.Type),  # Constructor operators
            (r'[:!#$%&*+.\\/<=>?@^|~-]+', Operator),  # Other operators
            (r'[`].+[`]', Operator),
            #  Numbers
            (r'\d+[eE][+-]?\d+', Number.Float),
            (r'\d+\.\d+([eE][+-]?\d+)?', Number.Float),
            (r'0[oO][0-7]+', Number.Oct),
            (r'0[xX][\da-fA-F]+', Number.Hex),
            (r'0[bB][01]+', Number.Bin),
            (r'\d+', Number.Integer),
            #  Character/String Literals
            (r"'", String.Char, 'character'),
            (r'"', String, 'string'),
            #  Special
            #(r'\[\]', Keyword.Type),
            (r'\(\)', Name.Builtin),
            (r'[][(),;{}]', Punctuation),
        ],
        'import': [
            # Import statements
            (r'\s+', Text),
            (r'"', String, 'string'),
            # after "funclist" state
            (r'\)', Punctuation, '#pop'),
            (r'qualified\b', Comment.Preproc),
            # import X as Y hiding (functions)
            (r'([' + uni.Lu + r'][\w.]*)(\s+)(as)(\s+)([' + uni.Lu + r'][\w.]*)(\s+)(hiding)(\s+)(\()',
             bygroups(Name.Namespace, Text, Comment.Preproc, Text, Name.Namespace, Text,
                 Comment.Preproc, Text, Punctuation), 'funclist'),
            # import X as Y
            (r'([' + uni.Lu + r'][\w.]*)(\s+)(as)(\s+)([' + uni.Lu + r'][\w.]*)',
             bygroups(Name.Namespace, Text, Comment.Preproc, Text, Name.Namespace), '#pop'),
            # import X hiding (functions)
            (r'([' + uni.Lu + r'][\w.]*)(\s+)(hiding)(\s+)(\()',
             bygroups(Name.Namespace, Text, Comment.Preproc, Text, Punctuation), 'funclist'),
            # import X (functions)
            (r'([' + uni.Lu + r'][\w.]*)(\s+)(\()',
             bygroups(Name.Namespace, Text, Punctuation), 'funclist'),
            # import X
            (r'[\w.]+', Name.Namespace, '#pop'),
        ],
        'module': [
            (r'\s+', Text),
            (r'([' + uni.Lu + r'][\w.]*)(\s+)(\()',
             bygroups(Name.Namespace, Text, Punctuation), 'funclist'),
            (r'[' + uni.Lu + r'][\w.]*', Name.Namespace, '#pop'),
        ],
        'funclist': [
            (r'\s+', Text),
            (r'[' + uni.Lu + r']\w*', Keyword.Type),
            (r'(_[\w\']+|[' + uni.Ll + r'][\w\']*)', Name.Function),
            (r'--(?![!#$%&*+./<=>?@^|_~:\\]).*?$', Comment.Single),
            (r'\{-', Comment.Multiline, 'comment'),
            (r',', Punctuation),
            (r'[:!#$%&*+.\\/<=>?@^|~-]+', Operator),
            # (HACK, but it makes sense to push two instances, believe me)
            (r'\(', Punctuation, ('funclist', 'funclist')),
            (r'\)', Punctuation, '#pop:2'),
        ],
        # NOTE: the next four states are shared in the AgdaLexer; make sure
        # any change is compatible with Agda as well or copy over and change
        'comment': [
            # Multiline Comments
            (r'[^-{}]+', Comment.Multiline),
            (r'\{-', Comment.Multiline, '#push'),
            (r'-\}', Comment.Multiline, '#pop'),
            (r'[-{}]', Comment.Multiline),
        ],
        'character': [
            # Allows multi-chars, incorrectly.
            (r"[^\\']'", String.Char, '#pop'),
            (r"\\", String.Escape, 'escape'),
            ("'", String.Char, '#pop'),
        ],
        'string': [
            (r'[^\\"]+', String),
            (r"\\", String.Escape, 'escape'),
            ('"', String, '#pop'),
        ],
        'escape': [
            (r'[abfnrtv"\'&\\]', String.Escape, '#pop'),
            (r'\^[][' + uni.Lu + r'@^_]', String.Escape, '#pop'),
            ('|'.join(ascii), String.Escape, '#pop'),
            (r'o[0-7]+', String.Escape, '#pop'),
            (r'x[\da-fA-F]+', String.Escape, '#pop'),
            (r'\d+', String.Escape, '#pop'),
            (r'\s+\\', String.Escape, '#pop'),
        ],
    }


class Smt2Lexer(RegexLexer):
    """
    A SMT-Lib 2 parser
    """
    name = 'Smt2'
    aliases = ['smt2']
    filenames = ['*.smt2']
    mimetypes = ['text/x-smt2']

    # list of known keywords and builtins taken form vim 6.4 scheme.vim
    # syntax file.
    keywords = (
        'declare-const', 'declare-fun', 'define-fun', 'assert', 'check-sat',
        'get-model', 'get-value', 'echo', 'exit', 'error',
        'sat', 'unsat', 'unknown', 'model', 'set-option', 'set-logic'
    )
    sorts = (
        'Int', 'Bool'
    )
    builtins = (
        '*', '+', '-', '/', '<', '<=', '=', '>', '>=', 'and', 'or', 'distinct',
        'not'
    )

    # valid names for identifiers
    # well, names can only not consist fully of numbers
    # but this should be good enough for now
    valid_name = r'[\w!$%&*+,/:<=>?@^~|-]+'

    tokens = {
        'root': [
            # the comments
            # and going to the end of the line
            (r';.*$', Comment.Single),
            # multi-line comment
            (r'#\|', Comment.Multiline, 'multiline-comment'),
            # commented form (entire sexpr folliwng)
            (r'#;\s*\(', Comment, 'commented-form'),
            # signifies that the program text that follows is written with the
            # lexical and datum syntax described in r6rs
            (r'#!r6rs', Comment),

            # whitespaces - usually not relevant
            (r'\s+', Text),

            # numbers
            (r'-?\d+\.\d+', Number.Float),
            (r'-?\d+', Number.Integer),
            # support for uncommon kinds of numbers -
            # have to figure out what the characters mean
            # (r'(#e|#i|#b|#o|#d|#x)[\d.]+', Number),

            # strings, symbols and characters
            (r'"(\\\\|\\"|[^"])*"', String),
            (r"'" + valid_name, String.Symbol),
            (r"#\\([()/'\"._!§$%& ?=+-]|[a-zA-Z0-9]+)", String.Char),

            # constants
            (r'(true|false)', Name.Constant),

            # special operators
            (r"('|#|`|,@|,|\.)", Operator),

            # highlight the keywords
            ('(%s)' % '|'.join(re.escape(entry) for entry in keywords),
             Keyword.Reserved),

            # highlight the sorts
            ('(%s)' % '|'.join(re.escape(entry) for entry in sorts),
             Keyword.Type),

            # first variable in a quoted string like
            # '(this is syntactic sugar)
            (r"(?<='\()" + valid_name, Name.Variable),
            (r"(?<=#\()" + valid_name, Name.Variable),

            # highlight the builtins
            ("(?<=\()(%s)" % '|'.join(re.escape(entry) + '\s+' for entry in builtins),
             Name.Builtin),

            # the remaining functions
            (r'(?<=\()' + valid_name, Name.Function),
            # find the remaining variables
            (valid_name, Name.Variable),

            # the famous parentheses!
            (r'(\(|\))', Punctuation),
            (r'(\[|\])', Punctuation),
        ],
        'multiline-comment': [
            (r'#\|', Comment.Multiline, '#push'),
            (r'\|#', Comment.Multiline, '#pop'),
            (r'[^|#]+', Comment.Multiline),
            (r'[|#]', Comment.Multiline),
        ],
        'commented-form': [
            (r'\(', Comment, '#push'),
            (r'\)', Comment, '#pop'),
            (r'[^()]+', Comment),
        ],
    }

class PicatLexer(RegexLexer):
    """
    Lexer for Picat files.
    """
    name = 'Picat'
    aliases = ['picat']
    filenames = ['*.pi']
    mimetypes = ['text/x-picat']

    flags = re.UNICODE | re.MULTILINE

    builtins = (
        'new_array', 'foreach', 'end', 'solve', 'abs'
    )

    tokens = {
        'root': [
            (r'\.\.', Operator),
            # (r'^#.*', Comment.Single),
            (r'/\*', Comment.Multiline, 'nested-comment'),
            (r'%.*', Comment.Single),
            # character literal
            (r'0\'.', String.Char),
            (r'0b[01]+', Number.Bin),
            (r'0o[0-7]+', Number.Oct),
            (r'0x[0-9a-fA-F]+', Number.Hex),
            # literal with prepended base
            (r'\d\d?\'[a-zA-Z0-9]+', Number.Integer),
            (r'(\d+\.(?=[^\.])\d*|\d*\.\d+)([eE][+-]?[0-9]+)?', Number.Float),
            (r'\d+', Number.Integer),
            (r'[\[\](){}|.,;!]', Punctuation),
            (r':-|-->', Punctuation),
            (r'"(?:\\x[0-9a-fA-F]+\\|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|'
             r'\\[0-7]+\\|\\["\nabcefnrstv]|[^\\"])*"', String.Double),
            (r"'(?:''|[^'])*'", String.Atom),  # quoted atom
            # Needs to not be followed by an atom.
            # (r'=(?=\s|[a-zA-Z\[])', Operator),
            (r'is\b', Operator),
            (r'(=|!=|:=|==|!==|<|=<|<=|>|>=|::|in|notin)', Operator),
            (r'(#=|#!=|#<|#=<|#<=|#>|#>=)', Operator),
            (r'(<|>|=<|>=|==|=:=|=|/|//|\*|\+|-)(?=\s|[a-zA-Z0-9\[])',
             Operator),
            (r'(mod|div|not)\b', Operator),
            (r'_', Keyword),  # The don't-care variable

            # highlight the builtins
            ('(%s)' % '|'.join(re.escape(entry) for entry in builtins),
             Name.Builtin),

            (r'([a-z]+)(:)', bygroups(Name.Namespace, Punctuation)),
            (u'([a-z\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]'
             u'[\w$\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]*)'
             u'(\\s*)(:-|-->)',
             bygroups(Name.Function, Text, Operator)),  # function defn
            (u'([a-z\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]'
             u'[\w$\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]*)'
             u'(\\s*)(\\()',
             bygroups(Name.Function, Text, Punctuation)),
            (u'[a-z\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]'
             u'[\w$\u00c0-\u1fff\u3040-\ud7ff\ue000-\uffef]*',
             String.Atom),  # atom, characters
            # This one includes !
            (u'[#&*+\\-./:<=>?@\\\\^~\u00a1-\u00bf\u2010-\u303f]+',
             String.Atom),  # atom, graphics
            (r'[A-Z_]\w*', Name.Variable),
            (u'\\s+|[\u2000-\u200f\ufff0-\ufffe\uffef]', Text),
        ],
        'nested-comment': [
            (r'\*/', Comment.Multiline, '#pop'),
            (r'/\*', Comment.Multiline, '#push'),
            (r'[^*/]+', Comment.Multiline),
            (r'[*/]', Comment.Multiline),
        ],
    }
