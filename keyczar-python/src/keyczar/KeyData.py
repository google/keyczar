class KeyType: 
  def __init__(self, name, id, sizes, outputSize):
    self._name = name
    self.id = id
    self.sizes = sizes
    self.size = sizes[0]  #default size
    self.outputSize = outputSize

  def __str__(self):
    return self._name
  
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
    if KeyTypes.types.has_key(value):
      return KeyTypes.types[value]
  getType = staticmethod(getType)

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
  
  def read(data):
    """
    Return Key object constructed from JSON dictionary.
    
    @param data dictionary read from JSON file
    @return Key object
    """
    return Key(data['type'], data['hash'])
  read = staticmethod(read)

class KeyMetadata:
  def __init__(self, name, purpose, type, versions):
    self._name = name
    self._purpose = purpose
    self._type = type
    self._versions = versions
    
  def __str__(self):
    return "%s - %s - %s" % (self._name, self._purpose, self._type)
  
  def name(self):
    return self._name
  
  def purpose(self):
    return self._purpose
  
  def type(self):
    return self._type
  
  def versions(self):
    return self._versions
  
  def read(kmd):
    """
    Return KeyMetadata object constructed from JSON dictionary.
    
    @param kmd dictionary read from JSON file
    @return KeyMetadata object
    """
    return KeyMetadata(kmd['name'], kmd['purpose'], 
                       kmd['type'], kmd['versions'])
  read = staticmethod(read)