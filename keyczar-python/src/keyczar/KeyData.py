class KeyType: 
  def __init__(self, name, id, sizes, outputSize):
    self.name = name
    self.id = id
    self.sizes = sizes
    self.size = sizes[0]  #default size
    self.outputSize = outputSize

  def __str__(self):
    return self.name
  
  def outputSize(self):
    return self.outputSize
  
  def defaultSize(self):
    return self.sizes[0]
  
  def size(self):
    return self.size
  
  def setSize(self, newSize):
    if newSize in self.sizes:
      self.size = newSize
      
  def resetSize(self):
    self.size = self.defaultSize()

class KeyTypes:   
  AES = KeyType("AES", 0, [128, 192, 256], 0)
  HMAC_SHA1 = KeyType("HMAC-SHA1", 1, [256], 20)
  DSA_PRIV = KeyType("DSA Private", 2, [1024], 48)
  DSA_PUB = KeyType("DSA Public", 3, [1024], 48)
  RSA_PRIV = KeyType("RSA Private", 4, [2048, 1024, 768, 512], 256)
  RSA_PUB = KeyType("RSA Public", 4, [2048, 1024, 768, 512], 256)
  types = {AES.id : AES, HMAC_SHA1.id : HMAC_SHA1, DSA_PRIV.id : DSA_PRIV, 
           DSA_PUB.id : DSA_PUB, RSA_PRIV.id : RSA_PRIV, RSA_PUB.id : RSA_PUB}
  
  def getType(value):
    if types.has_key(value):
      return types[value]

class Key:
  """Parent class for Keyczar Keys"""

  def __init__(self, type, hash):
    self.type = type
    self.hash = hash
    
  def __str__(self):
    return "(%s %s)" % (self.type, self.hash)  

  def type(self):
    return self.type
  
  def size(self):
    return self.size
  
  def hash(self):
    return self.hash

class KeyMetadata:
  def __init__(self, name, purpose, type, versions):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.versions = versions
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)