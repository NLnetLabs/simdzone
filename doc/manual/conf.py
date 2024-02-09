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
  'sphinx_rtd_theme',
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

html_title = f'{project}, {version}'
html_theme = 'sphinx_rtd_theme'
#html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
html_static_path = ['_static']
html_theme_options = {
    'logo_only': False, # No logo (yet)
    'display_version': True
}

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
