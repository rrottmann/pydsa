# pydsa
DSA Signature Algorithm - A simple implementation in Python

## Generate your DSA keypair

The key generation is a crucial part in cryptography.
Although it is possible to write it in pure Python, the implementation
may be flawed or the key is not based on cryptographic secure random
numbers.

Because of this, I've omitted the keygen method and would recommend
building the key outside of Python.

I've included two sample keypairs. One 512 bit real world keypair and
an example keypair that could be used to manually verify the code.

If you want to try some more keys, here are additional samples:

~~~
# DSA key, 512 bits
{
    "Q": 1260021755928513788571599504438886461377936881217,
    "P": 13215802529071855551943313349879770394691927370711522722842622001745077211972890580640990748291114169465597253458597759821541714594668205612405531098743733,
    "G": 455276047485817069916277446743189730425377195217680631038889953605607728791921521615547377293778074804992911578317438998802842046309729006598780666658326,
    "pub": 3036404803411196033070069256170232409942989851179350334254820349265197216569566209172676966085463154256974657976616817584164365206502207073907472859238476,
    "priv": 279024187637732322086413868627746442116145320938
}
# DSA key, 512 bits
{
    "Q": 1341900549555124873064130204963147708769253581301,
    "P": 7432359888316154771263218275724280901131924575536161876179642361275610721524385726490308633552457445185120040662322772977088152988634728101226863046136581,
    "G": 1492257850168835134070466045257688315376150892012978487853819129156120580866745506490145142655023635369583736954729944890019656413604867081875127370443086,
    "pub": 7005989449884126047896047657721672005749055903600955133790719437011671925262647266511803606052447901765438966482199200282068327634086087235072658984799660,
    "priv": 775898251443508702569746196737915407724647185115
}
# DSA key, 1024 bits prime
{
    "Q": 1461461359677056032138425664688969714401096527653,
    "P": 113003610536769662365475438074349202902393371149098932488829763899759693942182221311951893491037065838678290591836787867236266829425427477322203921585701270997375076009060429934105831431797790713235693561718253840225010037389994367689434248899226231330475152082648849936270434981210830874017521600353881618277,
    "G": 96504423597250666602463350548382591669983630413397284533161601799828504875913402437338367980529992940898864793759282567968196860849581229764805627921115713088555922323634319263032762806965222542087676328725218634401760700374749451348066585982534624077588633442696948741889609514070233035695255374063221721717,
    "pub": 108995193903934240798564100451045627210748695124974357268916707208528553000170266840505861201457239168618690453605371832512801286701989019522907305372175334396049194915209672515965212302226018817730175446251842830527761730120646366217675171871247849970396570237026190763013764161366386690833417893072059869763,
    "priv": 936678825459923885095535567029229102235556154286
}
~~~

## Example

The following example will demonstrate the usage of this module.

### Code
~~~
import hashlib
from pydsa import dsa

dsa_key = {
    'Q': 1218442816993522937915646204915776994404649089503L,
    'P': 11220611807188583130302963536190351192186270126479330588604287699892081267588448305835704397593153801135202051719876685351614175538253684346816652027037363L,
    'G': 11189361631195852088154673407566885728548496486362662112597687161142104619469702160215294558351391466982303919803857229515093575816938371433954759500448775L,
    'pub': 4572510396595314270786423212039255215498677297795049756997099191729339616558419010431226927123876238239229467750410441342637393785565872285607741290303779L,
    'priv': 148102768779017960166999813987055538077373228390L}
text = """lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod
tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At 
vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd 
gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum 
dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor 
invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero 
eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no 
sea takimata sanctus est Lorem ipsum dolor sit amet."""
m = hashlib.sha1()
m.update(text)
message = int("0x" + m.hexdigest(), 0)
sig = dsa.dsa_sign(dsa_key["Q"], dsa_key["P"], dsa_key["G"], dsa_key["priv"], message)
print "=" * 80
print "DSA SIGNATURE EXAMPLE"
print "=" * 80
print "DSA Keypair:"
for k in dsa_key.keys():
    print k, ':', str(dsa_key[k])
print "-" * 80
print "Text:"
print text
print "-" * 80
print "SHA-1:",
print message
print "-" * 80
print "DSA Signature:",
print sig
print "-" * 80
print "Verify:",
print dsa.dsa_verify(sig[0], sig[1], dsa_key["G"], dsa_key["P"], dsa_key["Q"], dsa_key["pub"], message)
print "-" * 80
~~~

### Output:

~~~
================================================================================
DSA SIGNATURE EXAMPLE
================================================================================
DSA Keypair:
Q : 1218442816993522937915646204915776994404649089503
P : 11220611807188583130302963536190351192186270126479330588604287699892081267588448305835704397593153801135202051719876685351614175538253684346816652027037363
pub : 4572510396595314270786423212039255215498677297795049756997099191729339616558419010431226927123876238239229467750410441342637393785565872285607741290303779
G : 11189361631195852088154673407566885728548496486362662112597687161142104619469702160215294558351391466982303919803857229515093575816938371433954759500448775
priv : 148102768779017960166999813987055538077373228390
--------------------------------------------------------------------------------
Text:
lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod
tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At
vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd
gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum
dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor
invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero
eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no
sea takimata sanctus est Lorem ipsum dolor sit amet.
--------------------------------------------------------------------------------
SHA-1: 15756661315799901065974520410262757362863199659
--------------------------------------------------------------------------------
DSA Signature: (1083487672663272963123471937064532340846466682277L, 325593530571084514925270065278707164203430125451L)
--------------------------------------------------------------------------------
Verify: True
--------------------------------------------------------------------------------
~~~

## Run the doctests

In order to test the module, I've included simple doctests.

Please note that DSA signatures change each time as a random
number gets picked. Therefore I do only check the length of the
returning tuple.

~~~
python pydsa/dsa.py -v
Trying:
    import hashlib
Expecting nothing
ok
Trying:
    import dsa
Expecting nothing
ok
Trying:
    m = hashlib.sha1()
Expecting nothing
ok
Trying:
    m.update("ABCDE")
Expecting nothing
ok
Trying:
    message = int("0x" + m.hexdigest(), 0)
Expecting nothing
ok
Trying:
    dsa_key = {
        'Q': 11,
        'P': 23,
        'G': 4,
        'pub': 8,
        'priv': 7}
Expecting nothing
ok
Trying:
    sig = dsa.dsa_sign(dsa_key["Q"], dsa_key["P"], dsa_key["G"], dsa_key["priv"], message)
Expecting nothing
ok
Trying:
    print len(sig)
Expecting:
    2
ok
Trying:
    import hashlib
Expecting nothing
ok
Trying:
    import dsa
Expecting nothing
ok
Trying:
    m = hashlib.sha1()
Expecting nothing
ok
Trying:
    m.update("ABCDE")
Expecting nothing
ok
Trying:
    message = int("0x" + m.hexdigest(), 0)
Expecting nothing
ok
Trying:
    dsa_key = {
        'Q': 11,
        'P': 23,
        'G': 4,
        'pub': 8,
        'priv': 7}
Expecting nothing
ok
Trying:
    sig = (2,3)
Expecting nothing
ok
Trying:
    print dsa.dsa_verify(sig[0], sig[1], dsa_key["G"], dsa_key["P"], dsa_key["Q"], dsa_key["pub"], message)
Expecting:
    True
ok
5 items had no tests:
    __main__
    __main__._digits_of_n
    __main__._mod_inverse
    __main__._random_s
    __main__.modexp_lr_k_ary
2 items passed all tests:
   8 tests in __main__.dsa_sign
   8 tests in __main__.dsa_verify
16 tests in 7 items.
16 passed and 0 failed.
Test passed.
~~~
