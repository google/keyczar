import KeyData
import Reader
import simplejson

class FileReader(Reader):
  def __init__(self, location):
    self.location = location
    
  def metadata(self):
    metadata = simplejson.loads(open(self.location + "/meta").read())
    return KeyData.KeyMetadata.read(metadata)

  def key(self, version):
    keyData = simplejson.loads(open(self.location + "/" + str(version)).read())
    return KeyData.Key.read(keyData)