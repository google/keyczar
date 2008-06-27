class KeyczarFileReader:
  def __init__(self, location):
    self.location = location
    
  def metadata(self):
    metaFile = open(self.location + "/meta").read()
    output = metaFile.read()
    metaFile.close()
    return output
  
  def key(self, version):
    keyFile = open(self.location + "/" + str(version))
    output = keyFile.read()
    keyFile.close()
    return output