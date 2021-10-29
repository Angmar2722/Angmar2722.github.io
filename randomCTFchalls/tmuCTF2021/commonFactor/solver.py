from Crypto.Util.number import *
from sympy import *
import math

n = 2870378965838324591930716372043943202857808446139955114178972466357197191646555386310681233993639582571871810351336802365212612829432807326876330070965674249357286034347008657883629500396346167749508691814871533203247809103597516756034759095100637453841622270471713637175966387708675681650825362129940918643196769504213592200456774778948694877618977617011530883570013644245183319361244368215398610979149060320165814554577615652211730789657513270358973557241707978338139984414979470166202562114202380919071164176972055791789476453657467515306951139381362369978138151345609568127199377878026652554062731521632501476705069316208464363846111869669167682507916421047852441782552255491492824812854004513204360809331798274954243569021433963906972169417423418831314860109084130511234616069241809687828168649890352090249712449906176079861456197001597695071378819897916782564243557316380779536239285819430145429214343617897807321057453881231873109668847371444981597545948164776111805671836878974593063507806022594658899187647227705150195530817678931698098259376629125579883657290675365061062988342506737677539253213873486072882314916722654639439974767729667348308089822272618812141734747518190918131475394008358752485820114352585363697943409142405397187811488425763607870435598703473283558863875082511735753198985761770194691897333996772347209579690094484306582887604607085834235579991339081114877411129747659636913741732353593602493602935647498099959376575507080043282822039059772712513621914435714472997174303938650778721067511657786410145042462581432379653230157438512241441297394613009093982995995721488753402291657942043365728675978004538612865075473060797997060824242663659400972803009150895091065010288979279208343727383126907536910816233381252213949988179391769784859432462536001028414576853626404313552019318821609411415846740546897494827049963081729773556670009694396655902808674253954003664489541274216766985514320658655385155404804471285629385163182065527325960787883285164384400671878810956747078706832300082761043350763868511932582950753204256098035119847645083342729287063167616495769840389702639642784779646124394274187760742667519368210034941587941073935227051959905320338654629277413407444919186684576561532634097854731829455621571431402040561443044139818425476711378475625762558700335148767065032908314020963523681108498054768101383636397920349166462138683843364568104852099786972138269207828354678771871957631305996408564918629611147162610100969994085549017653854895147761379806516965159036735885697873629236958604838297316909096866364056640064200671318939446575088736134834054178902097259981395846912668763412552618135586399374878369079393695944896480784503275721233694160817424918386850099538763638119036532611566641652505437494379272489263685110137046574303306123483008690943610001403933721637756187395490525025216826398321326468190996213618276820580272764947465497924136451423383678199000687060571477421196675667167891260178408652655959836575935636974063946514718181746525031519883430143656783652516536859306736796341726896446635046579279623124614077795247335483809777
e1 = 12189833951051730908370223331850919218243946952509718500560332838832804241963905158328421240593088009803147267463017892895712859666255758374859924227795693977692365712139787589267299790301022569583587926463070427550028215313969101326713297706315888193599192042874908901003626554054277955414415385731879026734954423731345798786722561845058120971545040892322209486011914785265062492920550158388814114563652053556586072198675716423094480300266767587890740892336081818352390563087579428787330255230317293748493589325405374600751428190100372051406745392483110379355174892921101536441200795867134576643519454074015675127266952070892796128379921598800605300182483946129377809823776730697790309647647190307296418381398693697240748290194721934318854836676911877413259621512269954316351093519057413607079769428640924051837599266617014518297183874986708528679104069884291849234025193207298171674607085234765320663128701647504631036578515249726222498212335082588627266250272379931767054363936707282364911659508871646177814796817889070190457673852047527357122774587607849820636184925240369923701314690600711989307878295308586902537853388274176578719581752448488589031302166298788451585838083076238353895213222535414766363665801955518856592943846521495707362179018672726109435436743723238172556767198562368516144637629110267835795311939660130673691902395560229758574266655957155862216872908603510940031334166746559195296408939506394470132257044581183533463281253397503463926598923844457702097679565967501579961386522021817780961888842972793029114864422478835769322906292819387383748603289494044561725080616097794190650081867485792883883943744138857860775053197775476414639386004107927910470986208356664914803636501181816689051948285860692212458532201937837589900582214489550639269506433713180672869129866286880957012266595540883727015907677897402607614096813204000
e2 = 10685466258462426438601930063854796559353071021872734112422666943995273083147678402485604005469990666166510724614508657976179169486278649913444601773228981194010779012945440827279478889951033722845969569487499109114807920422465585370352647531485228491726069752258604141544095143726497561287074963919306162501333879324320431815063767836881722714585596416818455332140968159290951800146179728839649549885714902391429304093259377977040947324691472037003260741076844850530123289350979761389302226559515709663477520315215796685387805223395013156063533568746725754875786890572455450963004254041206457627272694223378868063657567852741748730175173641019445706089775572094353061394171203735646557579595881047090069929263278434116703002648581646489410683234908239597741887334283851760107425225954878508549100715448112116790430791154066542690753466803004681805878269979001221299212426591974298670638899337600244969172572955344326969720268282445856163235666525453179028071857247486445419793906307197739042430106158187925914823345884448535360673122213977744765084269696399126350806729338388901052234851028732099724640679744428962810579433414095277730427540297789173682400086721025827804724736734372677509987948167038979141434755652392244734118982644329505761227780128318076798321983092557417882569724665849318066642854479540185619304472196160849810402529549850401440730174222018187759986936759639741288629098555521157461858554745777119186003733147607872641752914478401134544544581877108606144844955497062864711396338329584713840695858914573229254445387595034317081334732222156791041901660170883047145528155203729023944309061959449827690809614300474069217485344927501901373264278607167662413547572497683805087479857076246143962932587232903893219862365333270757997373558132982228573327073639550742090562057353483860863787775987229835303262050707215194078693398663198
ct = 1295564702637495685309272079895645034267002212576577351176786924725825901033456751565363132227845395192636014504044948379030468685845611242265523726539023437126669783303765124723915472786629678436713048730755297486348344599742142845784560313837239832937917360379066282667491918054529416764918515780567145928364634646722930481542026187360739697820492335622597715014255829089436910724972509085963133800806856075152036053630879580926838241308921405124424958500485001162000846198656477271924822124768722799190195854806533587717469450248664509344104461703840455934612539385694033634268205463024167234754553081069919678171898669570723347606172526826003367647892759191360901723076962059024693433937573808414595918813154817183122218324304727720231993955442001953029300266308755291774280607633683770298830407751731984235360718897231362141728129903067324174378760053260419744395257753779565716943029464080442902252184316484343234160161564121269883788523966796266675498603214422442299610994620373055814615356464754724264668947373104292350153322562799134518201535870142301501474217531998628211638040128486684200215958700680344308113382908656637378359217107811764695801417920230331446471475336055801665419851805385433677261916024902543165187462517860936690178095112472342793009281361928879367602088695738746822374043544415398979893735410561210643701354068887205774369902436302903034048756740583183966251194450689131063910079690811851244607443172434856486129471747053074648343069627212505795579741010868965206480675568896896528625130571758075102146302306655426190892962618128161759734724982773347245232038629926619247273436934947196867813659364951484832193239178102156204300353342841972762595259292048840326449938071520689839586933982775979336248771535685895403976612898604059800532915376510948151614460338199157528220842025853852584958511622657382701623309639101678362821929006062524756352592131742510350318470015268920615837821556797760508924258618057921324240995910743034414956163701330735308503014893515707188853735706296571253748889626515245648558769422283608966241496382223293119306642490794180175154686106323945765280777140420938641267467633112805720348438191023736935327334544026698324629536721807051447503613438954736205208639453193587326470160505597834244792859179593877840449441035962707113092034561698560285482507381177956117498938436596192528337690808299050972992206796450167499247505347105318901580848542927515381051973057219542622235114029773502036331075236848879130640275120244541018979621405480997745366565533911987665660584132852855158311718515145400486762846976972483867689062569575052791463761762637757579908921446285546575036947648139847182684615282524513693899858284291993167395096893612172061860682116974864364966362118833708791957224527084022917788839602167742342150067548893185747653708657029597051779997866982601553339504636518951723213334104705177572536156329378433835224612846933662252315126902599937489337158843870992464520248466088492159756466651557918397098886626028193224320040156124777562920457488126430654110240828124538167742484933802988652725530546987842196376

e2 = e2 + 2
temp = GCD(e1, e2)

_1_50 = 1 << 50  # 2**50 == 1,125,899,906,842,624

def isqrt(x):
    if x < 0:
        raise ValueError('square root not defined for negative numbers')
    if x < _1_50:
        return int(math.sqrt(x))  # use math's sqrt() for small parameters
    n = int(x)
    if n <= 1:
        return n  # handle sqrt(0)==0, sqrt(1)==1
    r = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r     
        r = newr

def quadraticFormulaPositive(a, b, c):
    t1 = (-1) * b
    discriminant = (pow(b, 2)) - (4) * a * c
    t4 = isqrt(discriminant)
    return int( (t1) + t4 ) // ( 2 * a)

for k in range(2, 100000):
    guess = temp // k
    p4 = (e2 // guess) - 1
    p2 = (e1 // guess) - 1
    if( (GCD(p2+1, p4+1)==k)):
        if (isprime(p4) and isprime(p2)):
            temp2 = e2 // (p4 + 1)
            p3 = quadraticFormulaPositive(1, p2, -1*temp2)
            if (isprime(p3)): 
                if (p2.bit_length() <= 2048 and p3.bit_length() <= 2048 and p4.bit_length() <= 2048):break
    

#print(p2, p3, p4)
a = p2*p3*p4 
assert n%a == 0  

aTotient = (p2 - 1) * (p3 - 1) * (p4- 1)
e = 65537
d = inverse(e, aTotient)

flag = pow(ct, d, a)
print(long_to_bytes(flag))

#b'TMUCTF{Y35!!!__M4Y_N0t_4lW4y5_N33d_4ll_p21M3_f4c70R5}'
