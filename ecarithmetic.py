# Pcurve secp256k1
secp256k1 = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The prime in F_p
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field F_p
Acurve = 0; Bcurve = 7 # y^2 = x^3 + Acurve * x + Bcurve
gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
gPoint = (gx,gy) # This is the generator point. One of trillions possible

#Individual Transaction/Personal Information (example values)
privKeyHex = 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E
privKey = 75263518707598184987916378021939673586055614731957507592904438851787542395619
RandNum = 28695618543805844332113829720373285210420739438570883203839696518176414791234
HashOfThingToSign = 86032112319101611046176971828093669637772856272773459297323797145286374828050 # the hash of your message/transaction

def modular_inverse(a, n=secp256k1):
    """
    Euclidian Algorithm - Elliptic Curve Division
    """
    
    lm = 1
    hm = 0
    low = a%n
    high = n
    while low > 1:
        ratio = high/low
        nm = hm-lm*ratio
        new = high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ec_add(xp,yp,xq,yq):
    """
    Point addition - takes 2 points along the curve and computes where a line through them intersects the curve. The negative of the intersection point is used as a result of the addition.
    P + Q = R, or (x_p,y_p)+(x_q,y_q) = (x_r,y_r) 
    lamda = (yq-yp)/(xq-xp)
    xr = lamda^2 - xp - xq
    yr = lamda(xp-xr) - yp
    """
    
    lam = ((yq-yp) * modular_inverse(xq-xp,Pcurve)) % Pcurve
    xr = (lam*lam-xp-xq) % Pcurve
    yr = (lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def point_double(xp,yp):
    """
    Point doubling - takes the tangent of a single point and finds the intersection with the tangent line.
    lamda = (3(xp^2)+a)/(2yp)
    xr = lamda^2 - 2xp
    yr = lamda(xp-xr)-yp
    """
    
    LamNumer = 3*xp*xp+Acurve
    LamDenom = 2*yp
    Lam = (LamNumer * modular_inverse(LamDenom,Pcurve)) % Pcurve
    xr = (Lam*Lam-2*xp) % Pcurve
    yr = (Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ec_multiply(genX, genY, ScalarHex):
    """
    Double & add
    """
    
    if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(ScalarHex))[2:]
    Qx, Qy = genX, genY 
    for i in range (1, len(ScalarBin)):
        Qx, Qy = point_double(Qx, Qy)
        if ScalarBin[i] == "1":
            Qx, Qy = ec_add(Qx, Qy, genX, genY)
    return (Qx, Qy)
    
def gen_public_key_compressed(genPoint, privKey=privKeyHex):
    retPublicKey = ec_multiply(genPoint[0], genPoint[1], privKey)
    print "the uncompressed public key (HEX):"
    print "04" + "%064x" % retPublicKey[0] + "%064x" % retPublicKey[1]
    print "the Public Key - compressed:"
    # Y value for public key is odd
    if retPublicKey[1] % 2 == 1:
        print "03"+str(hex(retPublicKey[0])[2:-1]).zfill(64)
    # Y value is even
    else:
        print "02"+str(hex(retPublicKey[0])[2:-1]).zfill(64)

def gen_public_key_uncompressed(genPoint, privKey=privKeyHex):
    """
    Generater point times private key = Public key
    Q = dP
    """
    
    retPublicKey = ec_multiply(gPoint[0], gPoint[1], privKey)
    print "the private key (in base 10 format): " + str(privKey)
    print "the uncompressed public key (starts with '04' & is not the public address):"
    print "04",retPublicKey[0],retPublicKey[1]
    return retPublicKey

def gen_signature(genPoint, trulyRandomNumber=RandNum):
    xRandSignPoint, yRandSignPoint = ec_multiply(gPoint[0], gPoint[1], RandNum)
    r = xRandSignPoint % N
    print "r ="+str(r)
    s = ((HashOfThingToSign + r*privKey)*(modular_inverse(RandNum,N))) % N
    print "s ="+str(s)

def verify_signature(genPoint, hashOfThingToSign=HashOfThingToSign):
    w = modular_inverse(s,N)
    xu1, yu1 = ec_multiply(genPoint[0], genPoint[1], (HashOfThingToSign * w)%N)
    xu2, yu2 = ec_multiply(xPublicKey,yPublicKey,(r*w)%N)
    x,y = ec_add(xu1,yu1,xu2,yu2)
    truthValue = (r==x)
    print truthValue
    return truthValue
