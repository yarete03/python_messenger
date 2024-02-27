import rsa

pub, priv = rsa.newkeys(2048)

print(pub.save_pkcs1("PEM"))

with open("private.key", "wb") as f:
    f.write(priv.save_pkcs1("PEM"))