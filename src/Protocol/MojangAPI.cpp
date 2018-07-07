
// MojangAPI.cpp

// Implements the cMojangAPI class representing the various API points provided by Mojang's webservices, and a cache for their results

#include "Globals.h"
#include "MojangAPI.h"
#include "SQLiteCpp/Database.h"
#include "SQLiteCpp/Statement.h"
#include "../IniFile.h"
#include "json/json.h"
#include "mbedTLS++/BlockingSslClientSocket.h"
#include "mbedTLS++/SslConfig.h"
#include "../RankManager.h"
#include "../OSSupport/IsThread.h"
#include "../Root.h"





/** The maximum age for items to be kept in the cache. Any item older than this will be removed. */
const Int64 MAX_AGE = 7 * 24 * 60 * 60;  // 7 days ago

/** The maximum number of names to send in a single query */
const int MAX_PER_QUERY = 100;





#define DEFAULT_NAME_TO_UUID_SERVER     "api-mojang.apis.moe"
#define DEFAULT_NAME_TO_UUID_ADDRESS    "/profiles/minecraft"
#define DEFAULT_UUID_TO_PROFILE_SERVER  "sessionserver-mojang.apis.moe"
#define DEFAULT_UUID_TO_PROFILE_ADDRESS "/session/minecraft/profile/%UUID%?unsigned=false"






/** Returns the CA certificates that should be trusted for Mojang-related connections. */
static cX509CertPtr GetCACerts(void)
{
	static const char CertString[] =
		// GeoTrust root CA cert
		// Currently used for signing *.mojang.com's cert
		// Exported from Mozilla Firefox's built-in CA repository
		"-----BEGIN CERTIFICATE-----\n"
		"MIIGCTCCBPGgAwIBAgISA8UaD9QF8DW5DvGrsUUkl79PMA0GCSqGSIb3DQEBCwUA\n"
		"MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n"
		"ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODA3MDcwMDMxNTZaFw0x\n"
		"ODEwMDUwMDMxNTZaMBUxEzARBgNVBAMMCiouYXBpcy5tb2UwggEiMA0GCSqGSIb3\n"
		"DQEBAQUAA4IBDwAwggEKAoIBAQDLnvdAJE/fyKEmqpI9BEquQyLSehy+afNC1T8d\n"
		"HpFvQyixB0KbQwHkxWqcx0Lu/lZ5ZZ6k7IPcFVJ4kcnYYu9oDqHQoXNayOh8WUHn\n"
		"DiCANNodsvQiAun1ZPGDLd5vXNqfgF1dUcl/WnNOPc6My5YEhinLJDxTTi+HDGho\n"
		"EovFug9dHoqsDaWOix5Fqt4p9YY+FASGbx9sGpjCVVvzzyt7XRooHdfozzJyvk5V\n"
		"ptHLBbbbn1QWC0TwHdGh/rVtKfMjVu5FSdYE9vPhj8lyfyAOJ46NACV/5fyOp9k3\n"
		"ziA2qIFjPx+G3OdWncWE5IRyuzdWVu3WFgQzOtcvoaTO+1DnAgMBAAGjggMcMIID\n"
		"GDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC\n"
		"MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFP4225Gi4yZw0vfM4wXLlpcFesoLMB8G\n"
		"A1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAu\n"
		"BggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAv\n"
		"BggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8w\n"
		"HwYDVR0RBBgwFoIKKi5hcGlzLm1vZYIIYXBpcy5tb2Uwgf4GA1UdIASB9jCB8zAI\n"
		"BgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8v\n"
		"Y3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRp\n"
		"ZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGll\n"
		"cyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBv\n"
		"bGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5\n"
		"LzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2ACk8UZZUyDlluqpQ/FgH1Ldvv1h6\n"
		"KXLcpMMM9OVFR/R4AAABZHJd8TAAAAQDAEcwRQIhALc3DNIfhpKg+CX88rQLYhMK\n"
		"YSHmDkRyvJAyUYsLo/qqAiBOrvpDq/JX6RabquuAlwJ/PKDN/S/VlvKcSG9F6IOy\n"
		"cAB2AFWB1MIWkDYBSuoLm1c8U/DA5Dh4cCUIFy+jqh0HE9MMAAABZHJd9JMAAAQD\n"
		"AEcwRQIgKXZSu1SXuX8S+IsrNfg05J0HT0ULL/V0z+ksVy9Z3OoCIQCZILFWqNC6\n"
		"TjzhzwphLXRItFsrq/KY5DpoDq6P5RnhrjANBgkqhkiG9w0BAQsFAAOCAQEAVIFt\n"
		"xA4eiYdgvGtvn5qFWTLAqxGWvFiKF9Vj0NLVWwYNahIXdUUwHIDq9hdSIDEDNXUM\n"
		"y8GsOaUTpaWB2NhJzEoGgBDwNjd4o+QeJC7ZCFt3Uc8rCjCdFVJTp/nqbk2PHjNB\n"
		"WEBYnxECFjhqnKg/tbtg8uylPdwLtNfAwtc1eHyj50yrznrAWP/FKSYfuPRSBrZl\n"
		"ZpX2iemBGyuurK/S7T8IPqD2IRpMHSQpQj3nstrs6IKxigWIc9mHQcU8JJMfHZBb\n"
		"fWY/6WfuvSG4PxF4awdAEvqHeij4/OyD6hjW6nKkhaO1okYK9bbBkh4E0fAC+uKV\n"
		"D20ViOcavk2gekMAwg==\n"
		"-----END CERTIFICATE-----\n\n"

		"-----BEGIN CERTIFICATE-----\n"
		"MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n"
		"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
		"DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n"
		"SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n"
		"GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
		"AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n"
		"q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n"
		"SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n"
		"Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n"
		"a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n"
		"/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n"
		"AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n"
		"CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n"
		"bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n"
		"c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n"
		"VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n"
		"ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n"
		"MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n"
		"Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n"
		"AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n"
		"uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n"
		"wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n"
		"X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n"
		"PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n"
		"KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n"
		"-----END CERTIFICATE-----\n"
	;

	static auto X509Cert = [&]()
	{
		auto Cert = std::make_shared<cX509Cert>();
		VERIFY(0 == Cert->Parse(CertString, sizeof(CertString)));
		return Cert;
	}();

	return X509Cert;
}





/** Returns the config to be used for secure requests. */
static std::shared_ptr<const cSslConfig> GetSslConfig()
{
	static const std::shared_ptr<const cSslConfig> Config = []()
	{
		auto Conf = cSslConfig::MakeDefaultConfig(true);
		Conf->SetCACerts(GetCACerts());
		Conf->SetAuthMode(eSslAuthMode::Required);
		return Conf;
	}();
	return Config;
}





////////////////////////////////////////////////////////////////////////////////
// cMojangAPI::sProfile:

cMojangAPI::sProfile::sProfile(
	const AString & a_PlayerName,
	const cUUID & a_UUID,
	const Json::Value & a_Properties,
	Int64 a_DateTime
) :
	m_PlayerName(a_PlayerName),
	m_UUID(a_UUID),
	m_Textures(),
	m_TexturesSignature(),
	m_DateTime(a_DateTime)
{
	/*
	Example a_Profile contents:
	"properties":
	[
		{
			"name": "textures",
			"value": "eyJ0aW1lc3RhbXAiOjE0MDcwNzAzMjEyNzEsInByb2ZpbGVJZCI6ImIxY2FmMjQyMDJhODQxYTc4MDU1YTA3OWM0NjBlZWU3IiwicHJvZmlsZU5hbWUiOiJ4b2Z0IiwiaXNQdWJsaWMiOnRydWUsInRleHR1cmVzIjp7IlNLSU4iOnsidXJsIjoiaHR0cDovL3RleHR1cmVzLm1pbmVjcmFmdC5uZXQvdGV4dHVyZS9iNzc5YmFiZjVhNTg3Zjk0OGFkNjc0N2VhOTEyNzU0MjliNjg4Mjk1YWUzYzA3YmQwZTJmNWJmNGQwNTIifX19",
			"signature": "XCty+jGEF39hEPrPhYNnCX087kPaoCjYruzYI/DS4nkL5hbjnkSM5Rh15hnUyv/FHhC8OF5rif3D1tQjtMI19KSVaXoUFXpbJM8/+PB8GDgEbX8Fc3u9nYkzOcM/xfxdYsFAdFhLQMkvase/BZLSuPhdy9DdI+TCrO7xuSTZfYmmwVuWo3w5gCY+mSIAnqltnOzaOOTcly75xvO0WYpVk7nJdnR2tvSi0wfrQPDrIg/uzhX7p0SnDqijmBU4QaNez/TNKiFxy69dAzt0RSotlQzqkDbyVKhhv9a4eY8h3pXi4UMftKEj4FAKczxLImkukJXuOn5NN15/Q+le0rJVBC60/xjKIVzltEsMN6qjWD0lQjey7WEL+4pGhCVuWY5KzuZjFvgqszuJTFz7lo+bcHiceldJtea8/fa02eTRObZvdLxbWC9ZfFY0IhpOVKfcLdno/ddDMNMQMi5kMrJ8MZZ/PcW1w5n7MMGWPGCla1kOaC55AL0QYSMGRVEZqgU9wXI5M7sHGZKGM4mWxkbEJYBkpI/p3GyxWgV6v33ZWlsz65TqlNrR1gCLaoFCm7Sif8NqPBZUAONHYon0roXhin/DyEanS93WV6i6FC1Wisscjq2AcvnOlgTo/5nN/1QsMbjNumuMGo37sqjRqlXoPb8zEUbAhhztYuJjEfQ2Rd8="
		}
	]
	*/

	// Parse the Textures and TexturesSignature from the Profile:
	if (!a_Properties.isArray())
	{
		// Properties is not a valid array, bail out
		return;
	}
	Json::UInt Size = a_Properties.size();
	for (Json::UInt i = 0; i < Size; i++)
	{
		const Json::Value & Prop = a_Properties[i];
		AString PropName = Prop.get("name", "").asString();
		if (PropName != "textures")
		{
			continue;
		}
		m_Textures = Prop.get("value", "").asString();
		m_TexturesSignature = Prop.get("signature", "").asString();
		break;
	}  // for i - Properties[]
}





////////////////////////////////////////////////////////////////////////////////
// cMojangAPI::cUpdateThread:

class cMojangAPI::cUpdateThread :
	public cIsThread
{
	typedef cIsThread super;
public:
	cUpdateThread(cMojangAPI & a_MojangAPI) :
		super("cMojangAPI::cUpdateThread"),
		m_MojangAPI(a_MojangAPI)
	{
	}

	virtual ~cUpdateThread() override
	{
		// Notify the thread that it should stop:
		m_ShouldTerminate = true;
		m_evtNotify.Set();

		// Wait for the thread to actually finish work:
		Stop();
	}

protected:

	/** The cMojangAPI instance to update. */
	cMojangAPI & m_MojangAPI;

	/** The event used for notifying that the thread should terminate, as well as timing. */
	cEvent m_evtNotify;


	// cIsThread override:
	virtual void Execute(void) override
	{
		do
		{
			m_MojangAPI.Update();
		} while (!m_ShouldTerminate && !m_evtNotify.Wait(60 * 60 * 1000));  // Repeat every 60 minutes until termination request
	}
} ;





////////////////////////////////////////////////////////////////////////////////
// cMojangAPI:

cMojangAPI::cMojangAPI(void) :
	m_NameToUUIDServer(DEFAULT_NAME_TO_UUID_SERVER),
	m_NameToUUIDAddress(DEFAULT_NAME_TO_UUID_ADDRESS),
	m_UUIDToProfileServer(DEFAULT_UUID_TO_PROFILE_SERVER),
	m_UUIDToProfileAddress(DEFAULT_UUID_TO_PROFILE_ADDRESS),
	m_RankMgr(nullptr),
	m_UpdateThread(new cUpdateThread(*this))
{
}





cMojangAPI::~cMojangAPI()
{
	SaveCachesToDisk();
}





void cMojangAPI::Start(cSettingsRepositoryInterface & a_Settings, bool a_ShouldAuth)
{
	m_NameToUUIDServer     = a_Settings.GetValueSet("MojangAPI", "NameToUUIDServer",     DEFAULT_NAME_TO_UUID_SERVER);
	m_NameToUUIDAddress    = a_Settings.GetValueSet("MojangAPI", "NameToUUIDAddress",    DEFAULT_NAME_TO_UUID_ADDRESS);
	m_UUIDToProfileServer  = a_Settings.GetValueSet("MojangAPI", "UUIDToProfileServer",  DEFAULT_UUID_TO_PROFILE_SERVER);
	m_UUIDToProfileAddress = a_Settings.GetValueSet("MojangAPI", "UUIDToProfileAddress", DEFAULT_UUID_TO_PROFILE_ADDRESS);
	LoadCachesFromDisk();
	if (a_ShouldAuth)
	{
		m_UpdateThread->Start();
	}
}





cUUID cMojangAPI::GetUUIDFromPlayerName(const AString & a_PlayerName, bool a_UseOnlyCached)
{
	// Convert the playername to lowercase:
	AString lcPlayerName = StrToLower(a_PlayerName);

	// Request the cache to query the name if not yet cached:
	if (!a_UseOnlyCached)
	{
		AStringVector PlayerNames{ lcPlayerName };
		CacheNamesToUUIDs(PlayerNames);
	}

	// Retrieve from cache:
	cCSLock Lock(m_CSNameToUUID);
	cProfileMap::const_iterator itr = m_NameToUUID.find(lcPlayerName);
	if (itr == m_NameToUUID.end())
	{
		// No UUID found
		return {};
	}
	return itr->second.m_UUID;
}





AString cMojangAPI::GetPlayerNameFromUUID(const cUUID & a_UUID, bool a_UseOnlyCached)
{
	// Retrieve from caches:
	{
		cCSLock Lock(m_CSUUIDToProfile);
		auto itr = m_UUIDToProfile.find(a_UUID);
		if (itr != m_UUIDToProfile.end())
		{
			return itr->second.m_PlayerName;
		}
	}
	{
		cCSLock Lock(m_CSUUIDToName);
		auto itr = m_UUIDToName.find(a_UUID);
		if (itr != m_UUIDToName.end())
		{
			return itr->second.m_PlayerName;
		}
	}

	// Name not yet cached, request cache and retry:
	if (!a_UseOnlyCached)
	{
		CacheUUIDToProfile(a_UUID);
		return GetPlayerNameFromUUID(a_UUID, true);
	}

	// No value found, none queried. Return an error:
	return {};
}





std::vector<cUUID> cMojangAPI::GetUUIDsFromPlayerNames(const AStringVector & a_PlayerNames, bool a_UseOnlyCached)
{
	// Convert all playernames to lowercase:
	AStringVector PlayerNames;
	for (AStringVector::const_iterator itr = a_PlayerNames.begin(), end = a_PlayerNames.end(); itr != end; ++itr)
	{
		PlayerNames.push_back(StrToLower(*itr));
	}  // for itr - a_PlayerNames[]

	// Request the cache to populate any names not yet contained:
	if (!a_UseOnlyCached)
	{
		CacheNamesToUUIDs(PlayerNames);
	}

	// Retrieve from cache:
	size_t idx = 0;
	std::vector<cUUID> res;
	res.resize(PlayerNames.size());
	cCSLock Lock(m_CSNameToUUID);
	for (AStringVector::const_iterator itr = PlayerNames.begin(), end = PlayerNames.end(); itr != end; ++itr, ++idx)
	{
		cProfileMap::const_iterator itrN = m_NameToUUID.find(*itr);
		if (itrN != m_NameToUUID.end())
		{
			res[idx] = itrN->second.m_UUID;
		}
	}  // for itr - PlayerNames[]
	return res;
}





void cMojangAPI::AddPlayerNameToUUIDMapping(const AString & a_PlayerName, const cUUID & a_UUID)
{
	Int64 Now = time(nullptr);
	{
		cCSLock Lock(m_CSNameToUUID);
		m_NameToUUID[StrToLower(a_PlayerName)] = sProfile(a_PlayerName, a_UUID, "", "", Now);
	}
	{
		cCSLock Lock(m_CSUUIDToName);
		m_UUIDToName[a_UUID] = sProfile(a_PlayerName, a_UUID, "", "", Now);
	}
	NotifyNameUUID(a_PlayerName, a_UUID);
}





void cMojangAPI::AddPlayerProfile(const AString & a_PlayerName, const cUUID & a_UUID, const Json::Value & a_Properties)
{
	Int64 Now = time(nullptr);
	{
		cCSLock Lock(m_CSNameToUUID);
		m_NameToUUID[StrToLower(a_PlayerName)] = sProfile(a_PlayerName, a_UUID, "", "", Now);
	}
	{
		cCSLock Lock(m_CSUUIDToName);
		m_UUIDToName[a_UUID] = sProfile(a_PlayerName, a_UUID, "", "", Now);
	}
	{
		cCSLock Lock(m_CSUUIDToProfile);
		m_UUIDToProfile[a_UUID] = sProfile(a_PlayerName, a_UUID, a_Properties, Now);
	}
	NotifyNameUUID(a_PlayerName, a_UUID);
}





bool cMojangAPI::SecureRequest(const AString & a_ServerName, const AString & a_Request, AString & a_Response)
{
	// Connect the socket:
	cBlockingSslClientSocket Socket;
	Socket.SetSslConfig(GetSslConfig());
	Socket.SetExpectedPeerName(a_ServerName);
	if (!Socket.Connect(a_ServerName, 443))
	{
		LOGWARNING("%s: Can't connect to %s: %s", __FUNCTION__, a_ServerName.c_str(), Socket.GetLastErrorText().c_str());
		return false;
	}

	if (!Socket.Send(a_Request.c_str(), a_Request.size()))
	{
		LOGWARNING("%s: Writing SSL data failed: %s", __FUNCTION__, Socket.GetLastErrorText().c_str());
		return false;
	}

	// Read the HTTP response:
	unsigned char buf[1024];

	for (;;)
	{
		int ret = Socket.Receive(buf, sizeof(buf));

		if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE))
		{
			// This value should never be returned, it is handled internally by cBlockingSslClientSocket
			LOGWARNING("%s: SSL reading failed internally", __FUNCTION__);
			return false;
		}
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		{
			break;
		}
		if (ret < 0)
		{
			LOGWARNING("%s: SSL reading failed: -0x%x", __FUNCTION__, -ret);
			return false;
		}
		if (ret == 0)
		{
			break;
		}

		a_Response.append(reinterpret_cast<const char *>(buf), static_cast<size_t>(ret));
	}

	return true;
}





void cMojangAPI::LoadCachesFromDisk(void)
{
	try
	{
		// Open up the SQLite DB:
		SQLite::Database db("MojangAPI.sqlite", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
		db.exec("CREATE TABLE IF NOT EXISTS PlayerNameToUUID (PlayerName, UUID, DateTime)");
		db.exec("CREATE TABLE IF NOT EXISTS UUIDToProfile    (UUID, PlayerName, Textures, TexturesSignature, DateTime)");

		// Retrieve all entries:
		{
			SQLite::Statement stmt(db, "SELECT PlayerName, UUID, DateTime FROM PlayerNameToUUID");
			while (stmt.executeStep())
			{
				AString PlayerName = stmt.getColumn(0);
				AString StringUUID = stmt.getColumn(1);
				Int64 DateTime     = stmt.getColumn(2);

				cUUID UUID;
				if (!UUID.FromString(StringUUID))
				{
					continue;  // Invalid UUID
				}

				m_NameToUUID[StrToLower(PlayerName)] = sProfile(PlayerName, UUID, "", "", DateTime);
				m_UUIDToName[UUID] = sProfile(PlayerName, UUID, "", "", DateTime);
			}
		}
		{
			SQLite::Statement stmt(db, "SELECT PlayerName, UUID, Textures, TexturesSignature, DateTime FROM UUIDToProfile");
			while (stmt.executeStep())
			{
				AString PlayerName        = stmt.getColumn(0);
				AString StringUUID        = stmt.getColumn(1);
				AString Textures          = stmt.getColumn(2);
				AString TexturesSignature = stmt.getColumn(2);
				Int64 DateTime            = stmt.getColumn(4);

				cUUID UUID;
				if (!UUID.FromString(StringUUID))
				{
					continue;  // Invalid UUID
				}

				m_UUIDToProfile[UUID] = sProfile(PlayerName, UUID, Textures, TexturesSignature, DateTime);
			}
		}
	}
	catch (const SQLite::Exception & ex)
	{
		LOGINFO("Loading MojangAPI cache failed: %s", ex.what());
	}
}





void cMojangAPI::SaveCachesToDisk(void)
{
	try
	{
		// Open up the SQLite DB:
		SQLite::Database db("MojangAPI.sqlite", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
		db.exec("CREATE TABLE IF NOT EXISTS PlayerNameToUUID (PlayerName, UUID, DateTime)");
		db.exec("CREATE TABLE IF NOT EXISTS UUIDToProfile (UUID, PlayerName, Textures, TexturesSignature, DateTime)");

		// Remove all entries:
		db.exec("DELETE FROM PlayerNameToUUID");
		db.exec("DELETE FROM UUIDToProfile");

		// Save all cache entries - m_PlayerNameToUUID:
		Int64 LimitDateTime = time(nullptr) - MAX_AGE;
		{
			SQLite::Statement stmt(db, "INSERT INTO PlayerNameToUUID(PlayerName, UUID, DateTime) VALUES (?, ?, ?)");
			cCSLock Lock(m_CSNameToUUID);
			for (auto & NameToUUID : m_NameToUUID)
			{
				auto & Profile = NameToUUID.second;
				if (Profile.m_DateTime < LimitDateTime)
				{
					// This item is too old, do not save
					continue;
				}
				stmt.bind(1, Profile.m_PlayerName);
				stmt.bind(2, Profile.m_UUID.ToShortString());
				stmt.bind(3, Profile.m_DateTime);
				stmt.exec();
				stmt.reset();
			}
		}

		// Save all cache entries - m_UUIDToProfile:
		{
			SQLite::Statement stmt(db, "INSERT INTO UUIDToProfile(UUID, PlayerName, Textures, TexturesSignature, DateTime) VALUES (?, ?, ?, ?, ?)");
			cCSLock Lock(m_CSUUIDToProfile);
			for (auto & UUIDToProfile : m_UUIDToProfile)
			{
				auto & Profile = UUIDToProfile.second;
				if (Profile.m_DateTime < LimitDateTime)
				{
					// This item is too old, do not save
					continue;
				}
				stmt.bind(1, Profile.m_UUID.ToShortString());
				stmt.bind(2, Profile.m_PlayerName);
				stmt.bind(3, Profile.m_Textures);
				stmt.bind(4, Profile.m_TexturesSignature);
				stmt.bind(5, Profile.m_DateTime);
				stmt.exec();
				stmt.reset();
			}
		}
	}
	catch (const SQLite::Exception & ex)
	{
		LOGINFO("Saving MojangAPI cache failed: %s", ex.what());
	}
}





void cMojangAPI::CacheNamesToUUIDs(const AStringVector & a_PlayerNames)
{
	// Create a list of names to query, by removing those that are already cached:
	AStringVector NamesToQuery;
	NamesToQuery.reserve(a_PlayerNames.size());
	{
		cCSLock Lock(m_CSNameToUUID);
		for (AStringVector::const_iterator itr = a_PlayerNames.begin(), end = a_PlayerNames.end(); itr != end; ++itr)
		{
			if (m_NameToUUID.find(*itr) == m_NameToUUID.end())
			{
				NamesToQuery.push_back(*itr);
			}
		}  // for itr - a_PlayerNames[]
	}  // Lock(m_CSNameToUUID)

	QueryNamesToUUIDs(NamesToQuery);
}





void cMojangAPI::QueryNamesToUUIDs(AStringVector & a_NamesToQuery)
{
	while (!a_NamesToQuery.empty())
	{
		// Create the request body - a JSON containing up to MAX_PER_QUERY playernames:
		Json::Value root;
		int Count = 0;
		AStringVector::iterator itr = a_NamesToQuery.begin(), end = a_NamesToQuery.end();
		for (; (itr != end) && (Count < MAX_PER_QUERY); ++itr, ++Count)
		{
			Json::Value req(*itr);
			root.append(req);
		}  // for itr - a_PlayerNames[]
		a_NamesToQuery.erase(a_NamesToQuery.begin(), itr);
		Json::FastWriter Writer;
		AString RequestBody = Writer.write(root);

		// Create the HTTP request:
		AString Request;
		Request += "POST " + m_NameToUUIDAddress + " HTTP/1.0\r\n";  // We need to use HTTP 1.0 because we don't handle Chunked transfer encoding
		Request += "Host: " + m_NameToUUIDServer + "\r\n";
		Request += "User-Agent: Cuberite\r\n";
		Request += "Connection: close\r\n";
		Request += "Content-Type: application/json\r\n";
		Request += Printf("Content-Length: %u\r\n", static_cast<unsigned>(RequestBody.length()));
		Request += "\r\n";
		Request += RequestBody;

		// Get the response from the server:
		AString Response;
		if (!SecureRequest(m_NameToUUIDServer, Request, Response))
		{
			continue;
		}

		// Check the HTTP status line:
		const AString Prefix("HTTP/1.1 200 OK");
		AString HexDump;
		if (Response.compare(0, Prefix.size(), Prefix))
		{
			LOGINFO("%s failed: bad HTTP status line received", __FUNCTION__);
			LOGD("Response: \n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
			continue;
		}

		// Erase the HTTP headers from the response:
		size_t idxHeadersEnd = Response.find("\r\n\r\n");
		if (idxHeadersEnd == AString::npos)
		{
			LOGINFO("%s failed: bad HTTP response header received", __FUNCTION__);
			LOGD("Response: \n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
			continue;
		}
		Response.erase(0, idxHeadersEnd + 4);

		// Parse the returned string into Json:
		Json::Reader reader;
		if (!reader.parse(Response, root, false) || !root.isArray())
		{
			LOGWARNING("%s failed: Cannot parse received data (NameToUUID) to JSON: \"%s\"", __FUNCTION__, reader.getFormattedErrorMessages().c_str());
			LOGD("Response body:\n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
			continue;
		}

		// Store the returned results into cache:
		Json::Value::UInt JsonCount = root.size();
		Int64 Now = time(nullptr);
		{
			cCSLock Lock(m_CSNameToUUID);
			for (Json::Value::UInt idx = 0; idx < JsonCount; ++idx)
			{
				Json::Value & Val = root[idx];
				AString JsonName = Val.get("name", "").asString();
				cUUID JsonUUID;
				if (!JsonUUID.FromString(Val.get("id", "").asString()))
				{
					continue;
				}
				m_NameToUUID[StrToLower(JsonName)] = sProfile(JsonName, JsonUUID, "", "", Now);
				NotifyNameUUID(JsonName, JsonUUID);
			}  // for idx - root[]
		}  // cCSLock (m_CSNameToUUID)

		// Also cache the UUIDToName:
		{
			cCSLock Lock(m_CSUUIDToName);
			for (Json::Value::UInt idx = 0; idx < JsonCount; ++idx)
			{
				Json::Value & Val = root[idx];
				AString JsonName = Val.get("name", "").asString();
				cUUID JsonUUID;
				if (!JsonUUID.FromString(Val.get("id", "").asString()))
				{
					continue;
				}
				m_UUIDToName[JsonUUID] = sProfile(JsonName, JsonUUID, "", "", Now);
			}  // for idx - root[]
		}
	}  // while (!NamesToQuery.empty())
}





void cMojangAPI::CacheUUIDToProfile(const cUUID & a_UUID)
{
	// Check if already present:
	{
		cCSLock Lock(m_CSUUIDToProfile);
		if (m_UUIDToProfile.find(a_UUID) != m_UUIDToProfile.end())
		{
			return;
		}
	}

	QueryUUIDToProfile(a_UUID);
}





void cMojangAPI::QueryUUIDToProfile(const cUUID & a_UUID)
{
	// Create the request address:
	AString Address = m_UUIDToProfileAddress;
	ReplaceString(Address, "%UUID%", a_UUID.ToShortString());

	// Create the HTTP request:
	AString Request;
	Request += "GET " + Address + " HTTP/1.0\r\n";  // We need to use HTTP 1.0 because we don't handle Chunked transfer encoding
	Request += "Host: " + m_UUIDToProfileServer + "\r\n";
	Request += "User-Agent: Cuberite\r\n";
	Request += "Connection: close\r\n";
	Request += "Content-Length: 0\r\n";
	Request += "\r\n";

	// Get the response from the server:
	AString Response;
	if (!SecureRequest(m_UUIDToProfileServer, Request, Response))
	{
		return;
	}

	// Check the HTTP status line:
	const AString Prefix("HTTP/1.1 200 OK");
	AString HexDump;
	if (Response.compare(0, Prefix.size(), Prefix))
	{
		LOGINFO("%s failed: bad HTTP status line received", __FUNCTION__);
		LOGD("Response: \n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
		return;
	}

	// Erase the HTTP headers from the response:
	size_t idxHeadersEnd = Response.find("\r\n\r\n");
	if (idxHeadersEnd == AString::npos)
	{
		LOGINFO("%s failed: bad HTTP response header received", __FUNCTION__);
		LOGD("Response: \n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
		return;
	}
	Response.erase(0, idxHeadersEnd + 4);

	// Parse the returned string into Json:
	Json::Reader reader;
	Json::Value root;
	if (!reader.parse(Response, root, false) || !root.isObject())
	{
		LOGWARNING("%s failed: Cannot parse received data (NameToUUID) to JSON: \"%s\"", __FUNCTION__, reader.getFormattedErrorMessages().c_str());
		LOGD("Response body:\n%s", CreateHexDump(HexDump, Response.data(), Response.size(), 16).c_str());
		return;
	}

	/* Example response:
	{
		"id": "b1caf24202a841a78055a079c460eee7",
		"name": "xoft",
		"properties":
		[
			{
				"name": "textures",
				"value": "eyJ0aW1lc3RhbXAiOjE0MDcwNzAzMjEyNzEsInByb2ZpbGVJZCI6ImIxY2FmMjQyMDJhODQxYTc4MDU1YTA3OWM0NjBlZWU3IiwicHJvZmlsZU5hbWUiOiJ4b2Z0IiwiaXNQdWJsaWMiOnRydWUsInRleHR1cmVzIjp7IlNLSU4iOnsidXJsIjoiaHR0cDovL3RleHR1cmVzLm1pbmVjcmFmdC5uZXQvdGV4dHVyZS9iNzc5YmFiZjVhNTg3Zjk0OGFkNjc0N2VhOTEyNzU0MjliNjg4Mjk1YWUzYzA3YmQwZTJmNWJmNGQwNTIifX19",
				"signature": "XCty+jGEF39hEPrPhYNnCX087kPaoCjYruzYI/DS4nkL5hbjnkSM5Rh15hnUyv/FHhC8OF5rif3D1tQjtMI19KSVaXoUFXpbJM8/+PB8GDgEbX8Fc3u9nYkzOcM/xfxdYsFAdFhLQMkvase/BZLSuPhdy9DdI+TCrO7xuSTZfYmmwVuWo3w5gCY+mSIAnqltnOzaOOTcly75xvO0WYpVk7nJdnR2tvSi0wfrQPDrIg/uzhX7p0SnDqijmBU4QaNez/TNKiFxy69dAzt0RSotlQzqkDbyVKhhv9a4eY8h3pXi4UMftKEj4FAKczxLImkukJXuOn5NN15/Q+le0rJVBC60/xjKIVzltEsMN6qjWD0lQjey7WEL+4pGhCVuWY5KzuZjFvgqszuJTFz7lo+bcHiceldJtea8/fa02eTRObZvdLxbWC9ZfFY0IhpOVKfcLdno/ddDMNMQMi5kMrJ8MZZ/PcW1w5n7MMGWPGCla1kOaC55AL0QYSMGRVEZqgU9wXI5M7sHGZKGM4mWxkbEJYBkpI/p3GyxWgV6v33ZWlsz65TqlNrR1gCLaoFCm7Sif8NqPBZUAONHYon0roXhin/DyEanS93WV6i6FC1Wisscjq2AcvnOlgTo/5nN/1QsMbjNumuMGo37sqjRqlXoPb8zEUbAhhztYuJjEfQ2Rd8="
			}
		]
	}
	*/

	// Store the returned result into caches:
	AString PlayerName = root.get("name", "").asString();
	if (PlayerName.empty())
	{
		// No valid playername, bail out
		return;
	}
	Json::Value Properties = root.get("properties", "");
	Int64 Now = time(nullptr);
	{
		cCSLock Lock(m_CSUUIDToProfile);
		m_UUIDToProfile[a_UUID] = sProfile(PlayerName, a_UUID, Properties, Now);
	}
	{
		cCSLock Lock(m_CSUUIDToName);
		m_UUIDToName[a_UUID] = sProfile(PlayerName, a_UUID, Properties, Now);
	}
	{
		cCSLock Lock(m_CSNameToUUID);
		m_NameToUUID[StrToLower(PlayerName)] = sProfile(PlayerName, a_UUID, Properties, Now);
	}
	NotifyNameUUID(PlayerName, a_UUID);
}





void cMojangAPI::NotifyNameUUID(const AString & a_PlayerName, const cUUID & a_UUID)
{
	// Notify the rank manager:
	cCSLock Lock(m_CSRankMgr);
	if (m_RankMgr != nullptr)
	{
		m_RankMgr->NotifyNameUUID(a_PlayerName, a_UUID);
	}
}





void cMojangAPI::Update(void)
{
	Int64 LimitDateTime = time(nullptr) - MAX_AGE;

	// Re-query all playernames that are stale:
	AStringVector PlayerNames;
	{
		cCSLock Lock(m_CSNameToUUID);
		for (const auto & NameToUUID : m_NameToUUID)
		{
			if (NameToUUID.second.m_DateTime < LimitDateTime)
			{
				PlayerNames.push_back(NameToUUID.first);
			}
		}  // for itr - m_NameToUUID[]
	}
	if (!PlayerNames.empty())
	{
		LOG("cMojangAPI: Updating name-to-uuid cache for %u names", static_cast<unsigned>(PlayerNames.size()));
		QueryNamesToUUIDs(PlayerNames);
	}

	// Re-query all profiles that are stale:
	std::vector<cUUID> ProfileUUIDs;
	{
		cCSLock Lock(m_CSUUIDToProfile);
		for (auto & UUIDToProfile : m_UUIDToProfile)
		{
			if (UUIDToProfile.second.m_DateTime < LimitDateTime)
			{
				ProfileUUIDs.push_back(UUIDToProfile.first);
			}
		}  // for itr - m_UUIDToProfile[]
	}
	if (!ProfileUUIDs.empty())
	{
		LOG("cMojangAPI: Updating uuid-to-profile cache for %u uuids", static_cast<unsigned>(ProfileUUIDs.size()));
		for (const auto & UUID : ProfileUUIDs)
		{
			QueryUUIDToProfile(UUID);
		}
	}
}
