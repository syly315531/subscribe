import base64

def encrypt_base64():
    with open("fly.txt","r") as f:
        encodeStr = base64.encodestring(f.read())
    with open("fly","w") as f:
        f.write(encodeStr)

if __name__=="__main__":
    encrypt_base64()