class Keyczar:
  """Abstract Keyczar class"""
    
  def __init__(self, reader):
    self.metadata = reader.metadata()
    self.keys = []
