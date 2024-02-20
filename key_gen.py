import rsa

pub, priv = rsa.newkeys(2048)

print(pub.save_pkcs1("PEM"))
print(priv.save_pkcs1("PEM"))