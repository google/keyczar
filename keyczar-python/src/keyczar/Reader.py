""" 
A Reader supports reading metadata and key info for key sets. 

@author steveweis@gmail.com (Steve Weis)
@author arkajit.dey@gmail.com (Arkajit Dey)
"""
class Reader:
  """ Interface providing supported methods (no implementation). """

  def metadata(self):
    """
    Return the KeyMetadata for the key set being read.
    
    @return KeyMetadata object
    """
    pass
  
  def key(self, version):
    """
    Return the Key corresponding to the given version.
    
    @param version, the integer version number
    @return Key object
    """
    pass