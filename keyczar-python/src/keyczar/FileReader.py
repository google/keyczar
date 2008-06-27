import KeyData
import simplejson

class Reader:
  "Place holder"

  def metadata(self):
    pass
  
  def key(self, version):
    pass

class FileReader(Reader):
  def __init__(self, location):
    self.location = location
    
  def metadata(self):
    metadata = simplejson.loads(open(self.location + "/meta").read())
    return KeyData.KeyMetadata(metadata['name'], metadata['purpose'], metadata['type'], metadata['versions'])

  def key(self, version):
    keyData = simplejson.loads(open(self.location + "/" + str(version)).read())
    print keyData
    return KeyData.Key(keyData['type'], keyData['hash'])