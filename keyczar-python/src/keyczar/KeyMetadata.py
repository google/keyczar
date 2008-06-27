class KeyMetadata:
  def __init__(self, name, purpose, type):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.versions = {}
    self.versionsByHash = {}
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)
  
  def addVerion(self, keyVersion):
    self.versions[keyVersion.id] = keyVersion