import os
import datetime

# -- Project information -----------------------------------------------------

project = '@PROJECT_NAME@'
year = datetime.datetime.now().year
copyright = f'2022-{year}, NLnet Labs'
author = 'NLnet Labs'

version = '@PROJECT_VERSION@'
release = '@PROJECT_VERSION@'

# -- General configuration ---------------------------------------------------

extensions = [
  'breathe',
  'sphinx.ext.todo',
  'sphinx.ext.ifconfig',
  'sphinx_tabs.tabs',
  'sphinx_copybutton',
  'sphinx.ext.intersphinx',
  'sphinx.ext.autosectionlabel',
  'notfound.extension'
]

needs_sphinx = '4.0'
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thunbs.db', '.DS_Store']

language = 'en'

# -- Options for HTML output -------------------------------------------------

html_theme = 'furo'
html_title = f'Documentation for simdzone by NLnet Labs'
html_css_files = ['css/nlnetlabs.css']

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# Keep the edit link pointed at the version being built on Read the Docs.
html_theme_options = {
    'source_repository': 'https://github.com/NLnetLabs/simdzone/',
    'source_branch': os.environ.get('READTHEDOCS_GIT_IDENTIFIER', 'main'),
    'source_directory': 'doc/manual/',
    'light_logo': 'images/nlnetlabs-wordmark.svg',
    'dark_logo': 'images/nlnetlabs-wordmark-white.svg',
    'light_css_variables': {
        'font-stack': '"NLnet Labs Montserrat", system-ui, sans-serif',
        'font-stack--headings': '"NLnet Labs Mackinac", Georgia, serif',
        'color-sidebar-link-text--top-level': 'var(--color-foreground-primary)',
        'color-sidebar-link-text': 'var(--color-foreground-secondary)',
        'color-link-underline': 'var(--color-brand-content)',
        'color-link-underline--visited': 'var(--color-brand-content)',
        'color-brand-visited': 'var(--color-brand-content)',
        'color-api-name': 'var(--color-brand-content)',
        'color-api-pre-name': 'var(--color-brand-content)',
        'color-sidebar-item-background--hover': 'var(--color-background-hover)',
        'color-foreground-primary': '#231f20',
        'color-foreground-secondary': '#625c5b',
        'color-foreground-muted': '#625c5b',
        'color-background-primary': '#ffffff',
        'color-background-secondary': '#f8f5f3',
        'color-background-hover': '#f1ebe7',
        'color-background-border': '#d8d0ca',
        'color-brand-primary': '#a83f0c',
        'color-brand-content': '#a83f0c',
    },
    'dark_css_variables': {
        'font-stack': '"NLnet Labs Montserrat", system-ui, sans-serif',
        'font-stack--headings': '"NLnet Labs Mackinac", Georgia, serif',
        'color-sidebar-link-text--top-level': 'var(--color-foreground-primary)',
        'color-sidebar-link-text': 'var(--color-foreground-secondary)',
        'color-link-underline': 'var(--color-brand-content)',
        'color-link-underline--visited': 'var(--color-brand-content)',
        'color-brand-visited': 'var(--color-brand-content)',
        'color-api-name': 'var(--color-brand-content)',
        'color-api-pre-name': 'var(--color-brand-content)',
        'color-sidebar-item-background--hover': 'var(--color-background-hover)',
        'color-foreground-primary': '#faf7f4',
        'color-foreground-secondary': '#c5bdb7',
        'color-foreground-muted': '#c5bdb7',
        'color-background-primary': '#231f20',
        'color-background-secondary': '#2d292a',
        'color-background-hover': '#383334',
        'color-background-border': '#655b56',
        'color-brand-primary': '#ff9b64',
        'color-brand-content': '#ff9b64',
    },
}

# Admonition colours: information, attention and warnings.
# Keep Furo's layout and icons; only override its colour variables.
for mode, information, attention, warning in (
    ('light', ('#625c5b', '#f1ebe7'), ('#a83f0c', '#feecdf'), ('#a83232', '#fbe9e7')),
    ('dark', ('#c5bdb7', '#383334'), ('#ff9b64', '#42312a'), ('#ffabab', '#482c30')),
):
    colours = html_theme_options[f'{mode}_css_variables']
    colours['color-admonition-background'] = 'var(--color-background-primary)'
    colours['color-admonition-title'] = information[0]
    colours['color-admonition-title-background'] = information[1]
    for kinds, (accent, background) in (
        (('note', 'seealso', 'hint', 'tip', 'admonition-todo'), information),
        (('attention', 'important', 'caution'), attention),
        (('warning', 'danger', 'error'), warning),
    ):
        for kind in kinds:
            colours[f'color-admonition-title--{kind}'] = accent
            colours[f'color-admonition-title-background--{kind}'] = background

html_favicon = '_static/favicon.ico'

html_static_path = ['_static']

primary_domain = 'c'
highlight_language = 'c'


# -- Options for Breathe -----------------------------------------------------

breathe_domain_by_extension = { 'h': 'c', 'c': 'c' }
breathe_show_define_initializer = True
breathe_show_include = True
breathe_projects = { 'doxygen': 'doxygen/xml' }
breathe_default_project = 'doxygen'


# -- Export variables to be used in RST --------------------------------------

rst_epilog = f'''
.. |project| replace:: {project}
.. |author| replace:: {author}
'''

# Specify custom source directory when building for Read the Docs
def setup(app):
  if 'READTHEDOCS' in os.environ:
    app.srcdir = '@PROJECT_SOURCE_DIR@' + '/doc/manual'
