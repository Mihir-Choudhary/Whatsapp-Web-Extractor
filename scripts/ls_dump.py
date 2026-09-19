import sqlite3, sys, json
db = sys.argv[1]
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
KEYS = ["last-wid-md","WALid","WANoiseInfo","WANoiseInfoIv","WAWebEncKeySalt","WebEncKeySalt",
        "Session","CanonicalRegistrationTraceId","WACachedProfilePicEURL","WADailyStatsStartTime",
        "WALangPhonePref","banzai:last_storage_flush","calls_tab_last_seen","selected_audio_input_device",
        "WABotListLastRequestedTimestamp","UsernameState","abprops-refresh-id","RSTData",
        "wa_voip_fieldstats_handoff_dedup_v1","hour-24-from-phone","contact-sync-refresh-seconds",
        "WANewslettersWasBootstrapped","MutexBlockStrategy","AbpropsWebRefreshId"]
for k in KEYS:
    r = con.execute("SELECT compression_type,last_access_time,value FROM data WHERE key=?", (k,)).fetchone()
    if not r: continue
    comp, lat, val = r
    if comp != 0:
        print(f"[{k}] (compressed type={comp}, {len(val)}B) -- skipped"); continue
    try: s = val.decode('utf-8', 'replace')
    except Exception: s = repr(val)
    print(f"\n=== {k} ===")
    print(s[:900])
