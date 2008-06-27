# for random testing
from Crypto.Hash import MD5
hash=MD5.new()
hash.update('message')
print hash.hexdigest()