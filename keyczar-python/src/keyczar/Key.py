class KeyType: 
  def __init__(self, name, id, sizes, outputSize):
    self.name = name
    self.id = id
    self.sizes = sizes
    self.outputSize = outputSize

  def __str__(self):
    return self.name

class Key:
  """Parent class for Keyczar Keys"""

  def __init__(self, type):
    self.type = type
  
  def type(self):
    return self.type
  
  def size(self):
    return self.size
  
  def hash(self):
    return self.hash
  
 
class KeyTypes:   
  AES = KeyType("AES", 0, [128, 192, 256], 0)
  HMAC_SHA1 = KeyType("HMAC-SHA1", 1, [256], 20)
  
  types = { AES.id : AES, HMAC_SHA1.id : HMAC_SHA1 }
