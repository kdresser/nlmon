import os.path, sys

def pfx2pp(p):
  """Put p after '' at head for list."""
  if p in sys.path:
    return
  sys.path.insert(1, p)

def set():
  if sys.platform.startswith('lin'):
    pfx2pp('/home/kelly/plib2')
  if sys.platform.startswith('win'):
    pfx2pp('N:\\P\\G\\plib2')
