
# Created with antsibull-docs 2.3.1.post0

# This file only contains a selection of the most common options. For a full list see the
# documentation:
# http://www.sphinx-doc.org/en/master/config

project = 'cloudera.cluster'
copyright = 'Cloudera, Inc.'

title = 'Cloudera Labs'
html_short_title = 'Cloudera Labs'

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.intersphinx', 'sphinx_antsibull_ext']

pygments_style = 'ansible'

highlight_language = 'YAML+Jinja'

html_theme = 'sphinx_ansible_theme'
html_show_sphinx = False

display_version = False

html_use_smartypants = True
html_use_modindex = False
html_use_index = False
html_copy_source = False

# See https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html#confval-intersphinx_mapping for the syntax
intersphinx_mapping = {
    'python': ('https://docs.python.org/2/', (None, '../python2.inv')),
    'python3': ('https://docs.python.org/3/', (None, '../python3.inv')),
    'jinja2': ('http://jinja.palletsprojects.com/', (None, '../jinja2.inv')),
    'ansible_devel': ('https://docs.ansible.com/ansible/devel/', (None, '../ansible_devel.inv')),
    # If you want references to resolve to a released Ansible version (say, `5`), uncomment and replace X by this version:
    # 'ansibleX': ('https://docs.ansible.com/ansible/X/', (None, '../ansibleX.inv')),
}

default_role = 'any'

nitpicky = True

html_css_files = [
    'css/cloudera.css',
]

html_last_updated_fmt = '%b %d, %Y'

html_theme_options = {
    'vcs_pageview_mode': 'edit',
    'documentation_home_url': 'https://github.com/cloudera-labs/',
    'topbar_links': {
        'Cloudera Data Platform (CDP)': 'https://www.cloudera.com/products/cloudera-data-platform.html',
        'Documentation': 'https://docs.cloudera.com/',
        'Downloads': 'https://www.cloudera.com/downloads.html',
        'Training': 'https://www.cloudera.com/about/training.html',
        'Certification': 'https://www.cloudera.com/about/training/certification.html',
    },
}

html_content = {
    'display_github': 'True',
}
